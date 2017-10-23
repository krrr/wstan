/* Just see Overlapped_ConnectEx; almost all of other codes are copied from overlapped.c from CPython */
#include "Python.h"
#include "structmember.h"
#include <WinSock2.h>
#include <MSWSock.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")


static LPFN_CONNECTEX ConnectEx = NULL;


static BOOL load_connectex(void) {
    /* dummy socket for WSAIoctl */
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        return FALSE;

	GUID guid = WSAID_CONNECTEX;
    DWORD dwBytes;
	if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guid, sizeof(guid),
		&ConnectEx, sizeof(ConnectEx),
		&dwBytes, NULL, NULL) != 0)
		return FALSE;

    closesocket(sock);
    return TRUE;
}


static BOOL (CALLBACK *Py_CancelIoEx)(HANDLE, LPOVERLAPPED) = NULL;
#if defined(MS_WIN32) && !defined(MS_WIN64)
#  define F_POINTER "k"
#  define T_POINTER T_ULONG
#else
#  define F_POINTER "K"
#  define T_POINTER T_ULONGLONG
#endif

/* Compatibility with Python 3.3 */
#if PY_VERSION_HEX < 0x03040000
#    define PyMem_RawMalloc PyMem_Malloc
#    define PyMem_RawFree PyMem_Free
#endif

#define F_HANDLE F_POINTER
#define F_ULONG_PTR F_POINTER
#define F_DWORD "k"
#define F_BOOL "i"
#define F_UINT "I"
#define T_HANDLE T_POINTER

enum {TYPE_NONE, TYPE_NOT_STARTED, TYPE_READ, TYPE_READINTO, TYPE_WRITE,
      TYPE_ACCEPT, TYPE_CONNECT, TYPE_DISCONNECT, TYPE_CONNECT_NAMED_PIPE,
TYPE_WAIT_NAMED_PIPE_AND_CONNECT};

static PyObject * SetFromWindowsErr(DWORD err) {
    PyObject *exception_type;

    if (err == 0)
        err = GetLastError();
    switch (err) {
        case ERROR_CONNECTION_REFUSED:
            exception_type = PyExc_ConnectionRefusedError;
            break;
        case ERROR_CONNECTION_ABORTED:
            exception_type = PyExc_ConnectionAbortedError;
            break;
        default:
            exception_type = PyExc_OSError;
    }
    return PyErr_SetExcFromWindowsErr(exception_type, err);
}

static int
parse_address(PyObject *obj, SOCKADDR *Address, int Length)
{
    Py_UNICODE *Host;
    unsigned short Port;
    unsigned long FlowInfo;
    unsigned long ScopeId;

    memset(Address, 0, Length);

    if (PyArg_ParseTuple(obj, "uH", &Host, &Port))
    {
        Address->sa_family = AF_INET;
        if (WSAStringToAddressW(Host, AF_INET, NULL, Address, &Length) < 0) {
            SetFromWindowsErr(WSAGetLastError());
            return -1;
        }
        ((SOCKADDR_IN*)Address)->sin_port = htons(Port);
        return Length;
    }
    else if (PyArg_ParseTuple(obj,
                              "uHkk;ConnectEx(): illegal address_as_bytes "
                              "argument", &Host, &Port, &FlowInfo, &ScopeId))
    {
        PyErr_Clear();
        Address->sa_family = AF_INET6;
        if (WSAStringToAddressW(Host, AF_INET6, NULL, Address, &Length) < 0) {
            SetFromWindowsErr(WSAGetLastError());
            return -1;
        }
        ((SOCKADDR_IN6*)Address)->sin6_port = htons(Port);
        ((SOCKADDR_IN6*)Address)->sin6_flowinfo = FlowInfo;
        ((SOCKADDR_IN6*)Address)->sin6_scope_id = ScopeId;
        return Length;
    }

    return -1;
}

typedef struct {
    PyObject_HEAD
    OVERLAPPED overlapped;
    /* For convenience, we store the file handle too */
    HANDLE handle;
    /* Error returned by last method call */
    DWORD error;
    /* Type of operation */
    DWORD type;
    union {
        /* Buffer allocated by us: TYPE_READ and TYPE_ACCEPT */
        PyObject *allocated_buffer;
        /* Buffer passed by the user: TYPE_WRITE and TYPE_READINTO */
        Py_buffer user_buffer;
    };
} OverlappedObject;

static PyObject *
Overlapped_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    OverlappedObject *self;
    HANDLE event = INVALID_HANDLE_VALUE;
    static char *kwlist[] = {"event", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|" F_HANDLE, kwlist, &event))
        return NULL;

    if (event == INVALID_HANDLE_VALUE) {
        event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (event == NULL)
            return SetFromWindowsErr(0);
    }

    self = PyObject_New(OverlappedObject, type);
    if (self == NULL) {
        if (event != NULL)
            CloseHandle(event);
        return NULL;
    }

    self->handle = NULL;
    self->error = 0;
    self->type = TYPE_NONE;
    self->allocated_buffer = NULL;
    memset(&self->overlapped, 0, sizeof(OVERLAPPED));
    memset(&self->user_buffer, 0, sizeof(Py_buffer));
    if (event)
        self->overlapped.hEvent = event;
    return (PyObject *)self;
}

static void
Overlapped_dealloc(OverlappedObject *self)
{
    DWORD bytes;
    DWORD olderr = GetLastError();
    BOOL wait = FALSE;
    BOOL ret;

    if (!HasOverlappedIoCompleted(&self->overlapped) &&
        self->type != TYPE_NOT_STARTED)
    {
        if (Py_CancelIoEx && Py_CancelIoEx(self->handle, &self->overlapped))
            wait = TRUE;

        Py_BEGIN_ALLOW_THREADS
        ret = GetOverlappedResult(self->handle, &self->overlapped,
                                  &bytes, wait);
        Py_END_ALLOW_THREADS

        switch (ret ? ERROR_SUCCESS : GetLastError()) {
            case ERROR_SUCCESS:
            case ERROR_NOT_FOUND:
            case ERROR_OPERATION_ABORTED:
                break;
            default:
                PyErr_Format(
                    PyExc_RuntimeError,
                    "%R still has pending operation at "
                    "deallocation, the process may crash", self);
                PyErr_WriteUnraisable(NULL);
        }
    }

    if (self->overlapped.hEvent != NULL)
        CloseHandle(self->overlapped.hEvent);

    switch (self->type) {
    case TYPE_READ:
    case TYPE_ACCEPT:
        Py_CLEAR(self->allocated_buffer);
        break;
    case TYPE_WRITE:
    case TYPE_READINTO:
        if (self->user_buffer.obj)
            PyBuffer_Release(&self->user_buffer);
        break;
    }
    PyObject_Del(self);
    SetLastError(olderr);
}

static PyObject * Overlapped_ConnectEx(OverlappedObject *self, PyObject *args) {
    char AddressBuf[sizeof(struct sockaddr_in6)];

    PyObject *AddressObj;
    PyBytesObject *bytes;
	
    SOCKET sock;
    if (!PyArg_ParseTuple(args, F_HANDLE "O!" "O!",
                          &sock, &PyTuple_Type, &AddressObj, &PyBytes_Type, &bytes))
        return NULL;

    if (self->type != TYPE_NONE) {
        PyErr_SetString(PyExc_ValueError, "operation already attempted");
        return NULL;
    }

    int length = sizeof(AddressBuf);
    SOCKADDR *Address = (SOCKADDR*)AddressBuf;
    length = parse_address(AddressObj, Address, length);
    if (length < 0)
        return NULL;

    self->type = TYPE_CONNECT;
    self->handle = (HANDLE)sock;

	// set tpo
	char optVal = TRUE;
	if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &optVal, sizeof(optVal)) != 0)
		return NULL;

	DWORD bytesSent;
	BOOL ret;
    Py_BEGIN_ALLOW_THREADS
	ret = ConnectEx(sock, (SOCKADDR*) Address, length,
			PyBytes_AS_STRING(bytes), (DWORD) PyBytes_GET_SIZE(bytes),
			&bytesSent, &self->overlapped);
    Py_END_ALLOW_THREADS

    self->error = (ret) ? ERROR_SUCCESS : WSAGetLastError();
    switch (self->error) {
        case ERROR_SUCCESS:
        case ERROR_IO_PENDING:
            Py_RETURN_NONE;
        default:
            self->type = TYPE_NOT_STARTED;
            return SetFromWindowsErr(self->error);
    }
}

static PyObject *
Overlapped_getresult(OverlappedObject *self, PyObject *args)
{
    BOOL wait = FALSE;
    DWORD transferred = 0;
    BOOL ret;
    DWORD err;

    if (!PyArg_ParseTuple(args, "|" F_BOOL, &wait))
        return NULL;

    if (self->type == TYPE_NONE) {
        PyErr_SetString(PyExc_ValueError, "operation not yet attempted");
        return NULL;
    }

    if (self->type == TYPE_NOT_STARTED) {
        PyErr_SetString(PyExc_ValueError, "operation failed to start");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    ret = GetOverlappedResult(self->handle, &self->overlapped, &transferred,
                              wait);
    Py_END_ALLOW_THREADS

    self->error = err = ret ? ERROR_SUCCESS : GetLastError();
    switch (err) {
        case ERROR_SUCCESS:
        case ERROR_MORE_DATA:
            break;
        case ERROR_BROKEN_PIPE:
            if (self->type == TYPE_READ || self->type == TYPE_READINTO)
                break;
            /* fall through */
        default:
            return SetFromWindowsErr(err);
    }

    switch (self->type) {
        case TYPE_READ:
            assert(PyBytes_CheckExact(self->allocated_buffer));
            if (transferred != PyBytes_GET_SIZE(self->allocated_buffer) &&
                _PyBytes_Resize(&self->allocated_buffer, transferred))
                return NULL;
            Py_INCREF(self->allocated_buffer);
            return self->allocated_buffer;
        default:
            return PyLong_FromUnsignedLong((unsigned long) transferred);
    }
}

static PyObject *
Overlapped_cancel(OverlappedObject *self)
{
    BOOL ret = TRUE;

    if (self->type == TYPE_NOT_STARTED
        || self->type == TYPE_WAIT_NAMED_PIPE_AND_CONNECT)
        Py_RETURN_NONE;

    if (!HasOverlappedIoCompleted(&self->overlapped)) {
        Py_BEGIN_ALLOW_THREADS
        if (Py_CancelIoEx)
            ret = Py_CancelIoEx(self->handle, &self->overlapped);
        else
            ret = CancelIo(self->handle);
        Py_END_ALLOW_THREADS
    }

    /* CancelIoEx returns ERROR_NOT_FOUND if the I/O completed in-between */
    if (!ret && GetLastError() != ERROR_NOT_FOUND)
        return SetFromWindowsErr(0);
    Py_RETURN_NONE;
}

static PyObject*
Overlapped_getaddress(OverlappedObject *self) {
    return PyLong_FromVoidPtr(&self->overlapped);
}

static PyObject*
Overlapped_getpending(OverlappedObject *self) {
    return PyBool_FromLong(!HasOverlappedIoCompleted(&self->overlapped) &&
                           self->type != TYPE_NOT_STARTED);
}

static PyMethodDef Overlapped_methods[] = {
	{"getresult", (PyCFunction) Overlapped_getresult,
     METH_VARARGS, NULL},
    {"cancel", (PyCFunction) Overlapped_cancel,
	 METH_NOARGS, NULL},
    {"ConnectEx", (PyCFunction) Overlapped_ConnectEx,
     METH_VARARGS, NULL},
    {NULL}
};

static PyMemberDef Overlapped_members[] = {
    {"error", T_ULONG,
     offsetof(OverlappedObject, error),
     READONLY, "Error from last operation"},
    {"event", T_HANDLE,
     offsetof(OverlappedObject, overlapped) + offsetof(OVERLAPPED, hEvent),
     READONLY, "Overlapped event handle"},
    {NULL}
};

static PyGetSetDef Overlapped_getsets[] = {
    {"address", (getter)Overlapped_getaddress, NULL,
     "Address of overlapped structure"},
    {"pending", (getter)Overlapped_getpending, NULL,
     "Whether the operation is pending"},
    {NULL},
};

PyTypeObject OverlappedType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    /* tp_name           */ "winasynctfo.Overlapped",
    /* tp_basicsize      */ sizeof(OverlappedObject),
    /* tp_itemsize       */ 0,
    /* tp_dealloc        */ (destructor) Overlapped_dealloc,
    /* tp_print          */ 0,
    /* tp_getattr        */ 0,
    /* tp_setattr        */ 0,
    /* tp_reserved       */ 0,
    /* tp_repr           */ 0,
    /* tp_as_number      */ 0,
    /* tp_as_sequence    */ 0,
    /* tp_as_mapping     */ 0,
    /* tp_hash           */ 0,
    /* tp_call           */ 0,
    /* tp_str            */ 0,
    /* tp_getattro       */ 0,
    /* tp_setattro       */ 0,
    /* tp_as_buffer      */ 0,
    /* tp_flags          */ Py_TPFLAGS_DEFAULT,
    /* tp_doc            */ "OVERLAPPED structure wrapper",
    /* tp_traverse       */ 0,
    /* tp_clear          */ 0,
    /* tp_richcompare    */ 0,
    /* tp_weaklistoffset */ 0,
    /* tp_iter           */ 0,
    /* tp_iternext       */ 0,
    /* tp_methods        */ Overlapped_methods,
    /* tp_members        */ Overlapped_members,
    /* tp_getset         */ Overlapped_getsets,
    /* tp_base           */ 0,
    /* tp_dict           */ 0,
    /* tp_descr_get      */ 0,
    /* tp_descr_set      */ 0,
    /* tp_dictoffset     */ 0,
    /* tp_init           */ 0,
    /* tp_alloc          */ 0,
    /* tp_new            */ Overlapped_new,
};

static struct PyModuleDef winasynctfo_module = {
    PyModuleDef_HEAD_INIT,
    "winasynctfo",
    NULL,
    -1,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_overlapped(void) {
	/* Ensure WSAStartup() called before initializing function pointers */
    auto _socket = PyImport_ImportModule("_overlapped");
    if (!_socket)
        return NULL;
	Py_DECREF(_socket);

    if (!load_connectex()) {
        return NULL;
    }
    auto hKernel32 = GetModuleHandleA("KERNEL32");
    *(FARPROC *)&Py_CancelIoEx = GetProcAddress(hKernel32, "CancelIoEx");

	if (PyType_Ready(&OverlappedType) < 0)
		return NULL;

    auto m = PyModule_Create(&winasynctfo_module);
    if (PyModule_AddObject(m, "Overlapped", (PyObject *)&OverlappedType) < 0)
		return NULL;
	return m;
}