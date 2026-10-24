/**
 * Host C JNI-table smoke fixture for exercise without Android.
 *
 * Implements a standalone mock JNIEnv interface conforming to standard
 * JNIEnv struct layouts (232 function pointers), allowing host execution
 * and Frida dynamic tracing tests.
 *
 * Compilation command:
 *   clang -shared -fPIC -o /tmp/libjni-host-smoke.dylib packages/coding-agent/test/fixtures/jni-host-smoke.c
 * or standalone binary:
 *   clang -o /tmp/jni-host-smoke packages/coding-agent/test/fixtures/jni-host-smoke.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void* jobject;
typedef void* jclass;
typedef void* jmethodID;
typedef void* jfieldID;
typedef void* jstring;
typedef int jint;
typedef int jsize;

typedef struct {
    char *name;
    char *signature;
    void *fnPtr;
} JNINativeMethod;

static jint mock_GetVersion(void *env) {
    (void)env;
    return 0x00010006; // JNI 1.6
}

static jclass mock_FindClass(void *env, const char *name) {
    (void)env;
    printf("[HostJni] FindClass called: %s\n", name ? name : "null");
    // Return dummy non-null pointer based on name
    return (jclass)(uintptr_t)0xCAFE0001;
}

static jmethodID mock_GetMethodID(void *env, jclass clazz, const char *name, const char *sig) {
    (void)env;
    (void)clazz;
    printf("[HostJni] GetMethodID called: %s %s\n", name ? name : "null", sig ? sig : "null");
    return (jmethodID)(uintptr_t)0xCAFE0002;
}

static void mock_CallVoidMethod(void *env, jobject obj, jmethodID methodID, ...) {
    (void)env;
    (void)obj;
    (void)methodID;
    printf("[HostJni] CallVoidMethod called (variadic)\n");
}

static void mock_CallVoidMethodA(void *env, jobject obj, jmethodID methodID, const void *args) {
    (void)env;
    (void)obj;
    (void)methodID;
    (void)args;
    printf("[HostJni] CallVoidMethodA called (typed non-variadic)\n");
}

static jint mock_RegisterNatives(void *env, jclass clazz, const JNINativeMethod *methods, jint nMethods) {
    (void)env;
    (void)clazz;
    printf("[HostJni] RegisterNatives called with %d methods\n", nMethods);
    for (int i = 0; i < nMethods; i++) {
        printf("  - Method %d: %s %s -> %p\n", i, methods[i].name, methods[i].signature, methods[i].fnPtr);
    }
    return 0; // JNI_OK
}

static void* dummy_fn(void) {
    return NULL;
}

// Full 232-entry JNI function table
typedef struct {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    void* reserved3;
    jint (*GetVersion)(void*);
    void* DefineClass;
    jclass (*FindClass)(void*, const char*);
    void* FromReflectedMethod;
    void* FromReflectedField;
    void* ToReflectedMethod;
    void* GetSuperclass;
    void* IsAssignableFrom;
    void* ToReflectedField;
    void* Throw;
    void* ThrowNew;
    void* ExceptionOccurred;
    void* ExceptionDescribe;
    void* ExceptionClear;
    void* FatalError;
    void* PushLocalFrame;
    void* PopLocalFrame;
    void* NewGlobalRef;
    void* DeleteGlobalRef;
    void* DeleteLocalRef;
    void* IsSameObject;
    void* NewLocalRef;
    void* EnsureLocalCapacity;
    void* AllocObject;
    void* NewObject;
    void* NewObjectV;
    void* NewObjectA;
    void* GetObjectClass;
    void* IsInstanceOf;
    jmethodID (*GetMethodID)(void*, jclass, const char*, const char*);
    void* CallObjectMethod;
    void* CallObjectMethodV;
    void* CallObjectMethodA;
    void* CallBooleanMethod;
    void* CallBooleanMethodV;
    void* CallBooleanMethodA;
    void* CallByteMethod;
    void* CallByteMethodV;
    void* CallByteMethodA;
    void* CallCharMethod;
    void* CallCharMethodV;
    void* CallCharMethodA;
    void* CallShortMethod;
    void* CallShortMethodV;
    void* CallShortMethodA;
    void* CallIntMethod;
    void* CallIntMethodV;
    void* CallIntMethodA;
    void* CallLongMethod;
    void* CallLongMethodV;
    void* CallLongMethodA;
    void* CallFloatMethod;
    void* CallFloatMethodV;
    void* CallFloatMethodA;
    void* CallDoubleMethod;
    void* CallDoubleMethodV;
    void* CallDoubleMethodA;
    void (*CallVoidMethod)(void*, jobject, jmethodID, ...);
    void (*CallVoidMethodV)(void*, jobject, jmethodID, void*);
    void (*CallVoidMethodA)(void*, jobject, jmethodID, const void*);
    /* Remaining entries up to 232 */
    void* entries[151];
    jint (*RegisterNatives)(void*, jclass, const JNINativeMethod*, jint);
    void* trailing[17];
} JNINativeInterfaceMock;

static JNINativeInterfaceMock g_mockInterface;
static const JNINativeInterfaceMock* g_pInterface = &g_mockInterface;
static void* g_mockJniEnv = (void*)&g_pInterface;

static void init_mock_interface(void) {
    void **slots = (void**)&g_mockInterface;
    for (size_t i = 0; i < sizeof(JNINativeInterfaceMock)/sizeof(void*); i++) {
        slots[i] = (void*)dummy_fn;
    }
    g_mockInterface.GetVersion = mock_GetVersion;
    g_mockInterface.FindClass = mock_FindClass;
    g_mockInterface.GetMethodID = mock_GetMethodID;
    g_mockInterface.CallVoidMethod = mock_CallVoidMethod;
    g_mockInterface.CallVoidMethodA = mock_CallVoidMethodA;
    g_mockInterface.RegisterNatives = mock_RegisterNatives;
}

// Exported JNI-style function that Frida can intercept
void Java_com_example_smoke_NativeSample_doWork(void *env, void *thiz) {
    (void)thiz;
    JNINativeInterfaceMock **pEnv = (JNINativeInterfaceMock**)env;
    JNINativeInterfaceMock *table = *pEnv;
    jint ver = table->GetVersion(env);
    printf("[HostJni] GetVersion: 0x%x\n", ver);

    jclass clz = table->FindClass(env, "com/example/smoke/TargetService");
    jmethodID mid = table->GetMethodID(env, clz, "authenticate", "(Ljava/lang/String;)V");
    table->CallVoidMethod(env, (jobject)0x1001, mid);
    if (table->CallVoidMethodA) {
        table->CallVoidMethodA(env, (jobject)0x1001, mid, NULL);
    }

    JNINativeMethod methods[] = {
        {"nativeEncrypt", "(Ljava/lang/String;)[B", (void*)dummy_fn},
        {"nativeVerify", "([B)Z", (void*)dummy_fn}
    };
    table->RegisterNatives(env, clz, methods, 2);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    init_mock_interface();
    printf("JNI Host Smoke PID: %d, Env: %p\n", getpid(), g_mockJniEnv);
    fflush(stdout);

    // Call native work once
    Java_com_example_smoke_NativeSample_doWork(g_mockJniEnv, NULL);
    return 0;
}
