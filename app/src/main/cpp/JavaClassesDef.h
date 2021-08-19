/**
 * Created by KXD on 2021/2/1.
 *
 * C++中用到的Java类的定义
 * _Clz结尾表示一个class; _Method结尾表示一个成员方法; _Param结尾表示方法的参数
 *
 */

#ifndef JAVA_CLASSES_DEF_H
#define JAVA_CLASSES_DEF_H

/*******------类分割线-------**********/

#define SecureUtil_Clz  "com/iscclockk/SecureUtil"

#define SecureUtil_getDeviceId_Method  "getDeviceId"
#define SecureUtil_getDeviceId_Param  "(Landroid/content/Context;)Ljava/lang/String;"

#define SecureUtil_getAppVersion_Method "getAppVersion"
#define SecureUtil_getAppVersion_Param "()Ljava/lang/String;"

#define SecureUtil_getChannel_Method "getChannel"
#define SecureUtil_getChannel_Param "()Ljava/lang/String;"

#define SecureUtil_showMeg_Method "showMeg"
#define SecureUtil_showMeg_Param "(Ljava/lang/String;)V"

#define SecureUtil_encryptData_Method "encryptData"
#define SecureUtil_encryptData_Param "(Landroid/content/Context;[B)[B"


#define SecureUtil_getSign_Method "getSign"
#define SecureUtil_getSign_Param "(Landroid/content/Context;)Ljava/lang/String;"

/*******------类分割线-------**********/


#endif //JAVA_CLASSES_DEF_H