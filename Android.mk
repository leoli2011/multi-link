LOCAL_PATH := $(call my-dir)

#########################

include $(CLEAR_VARS)
LOCAL_SRC_FILES :=  multilink.c ml_netlink.c ml_parse.c 

LOCAL_VENDOR_MODULE := true
LOCAL_MODULE := multilink

LOCAL_CFLAGS := -O2 -g -W -Wall -D__ANDROID__ -DIPV6 -DNO_SCRIPT -D_BSD_SOURCE \
                -Wno-unused-variable -Wno-unused-parameter -Werror

LOCAL_CFLAGS += -DMODEM_ENVIRONMENT 
LOCAL_CFLAGS += -Wno-missing-field-initializers

LOCAL_SYSTEM_SHARED_LIBRARIES := libc

LOCAL_SHARED_LIBRARIES := libnl3 libnl-route-3 libnl-cli-3 libyaml

LOCAL_C_INCLUDES := vendor/ff/external/libnl3/include
LOCAL_C_INCLUDES += vendor/ff/external/libyaml/include

include $(BUILD_EXECUTABLE)

# The configuration and init rc files of multilink.
include $(CLEAR_VARS)

LOCAL_MODULE := multilink.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_OWNER := ff
LOCAL_PROPRIETARY_MODULE := true
LOCAL_INIT_RC := multilink.rc

include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := multilink_us.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_OWNER := ff
LOCAL_PROPRIETARY_MODULE := true
include $(BUILD_PREBUILT)

include $(LOCAL_PATH)/tests/Android.mk
