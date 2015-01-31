LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := android_runtime      
LOCAL_SRC_FILES := android_runtime/libandroid_runtime.so
LOCAL_EXPORT_C_INCLUDES := android_runtime/include
include $(PREBUILT_SHARED_LIBRARY)   

include $(CLEAR_VARS)  
LOCAL_MODULE    := payload  
LOCAL_SRC_FILES := payload.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH) $(LOCAL_PATH)/android_runtime/include
LOCAL_SHARED_LIBRARIES := libandroid_runtime
LOCAL_LDLIBS += -llog
include $(BUILD_SHARED_LIBRARY)  

include $(CLEAR_VARS)
LOCAL_MODULE := missile
LOCAL_SRC_FILES := missile.c
include $(BUILD_EXECUTABLE)
