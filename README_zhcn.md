类似 [StringFog](https://github.com/MegatronKing/StringFog) 的一个 gradle 插件，
相对于原版，我做了以下的改动：
1. 为每个类生成字符串解密函数，这样可以防止 hook 唯一的解密函数来方便地获取密文和明文的对应关系；
2. 原版插件好像会将某些空字符串("") 替换为 null，这样会引发一些异常，也可能是我抄代码然后用错了；
3. 算法不能自定义，除非你自己修改插件源码，目前的算法是 native 层的 blowfish + java 层的简单异或，blowfish 的 box 是修改过的；
4. 配置有一些改变。

声明：
大部分代码都是直接抄的

使用方法：
1. 构建生成 StringMist 并将其添加到你本地的 maven 仓库；
2. 在 Project 的 build.gradle 中添加仓库和依赖；
```gradle
buildscript {
    repositories {
        maven{
            url uri('C:\\Users\\Administrator\\.m2\\repository')
        }
        jcenter()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:3.4.2'
        classpath 'com.wizd:stringmist:1.0'
    }
}
```
3. 在 Module 的 build.gradle 中应用插件和配置属性；
```gradle
apply plugin: 'stringmist'

stringmist {
    nativeInterfaceClass = 'com.wizd.usegradleplugin.NativeInterface'
    excludeClasses = []
    includeJars = ['nanohttpd.jar', 'okhttp.jar']
}
```
