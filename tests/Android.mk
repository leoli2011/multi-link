LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES :=  ml_count.c

LOCAL_VENDOR_MODULE := true
LOCAL_MODULE := ml_count
LOCAL_MODULE_TAGS := debug

LOCAL_CFLAGS := -O2 -g -W -Wall -Werror -Wno-unused-variable -Wno-unused-parameter


include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := modem_client.sh
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_TAGS := debug

include $(BUILD_PREBUILT)
