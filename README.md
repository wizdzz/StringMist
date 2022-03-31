[中文](https://github.com/wizdzz/StringMist/blob/master/README_zhcn.md)

# StringMist
Gradle plugin for encrypting string constant on Java<br>

The plugin seems like [StringFog](https://github.com/MegatronKing/StringFog), but I have added some interesting things.<br>
(Actually much of the code is just copy from StringFog directly.)<br>

## Funny stuff
This plugin generates a strDec method for every Java class to prevent the reverse engineer hooking the only strDec method on the original plugin.<br>
In the original one, it is easy to get the ciphertext and plaintext by that, I think that is one of the shortcoming. Furthermore, on the new version of JEB, it will be decrypted automatically and show the plaintext directly there.<br>
So, generating hooking code for every class and comming with different method names, seems like shitty and disgusting. And that is exactly what we want.<br>

## Something that is not perfect on original plugin
During plagiarisming code from StringFog, I have found that it will replace some empty string("") with null.<br>
That's not right and will cause some exceptions, maybe I just use it wrongly or I didn't know and didn't configure some setting. Anyway, I fixed it.<br>

## Shortcoming of this one
This one is not able to customize encrypt algorithm unless you modify the source code, now I use blowfish on native and simple XOR on Java, please note the init box of blowfish is unstandard.

## Usage
1. Build and add StringMit to your local maven repository;
2. Add local repositories and dependencies on target project(Project's build.gradle);
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
3. Apply plugin and set properties on Module's build.gradle;
```gradle
apply plugin: 'stringmist'

stringmist {
    nativeInterfaceClass = 'com.wizd.usegradleplugin.NativeInterface'
    excludeClasses = []
    includeJars = ['nanohttpd.jar', 'okhttp.jar']
}
```

## Screenshot
![Alt text](https://github.com/wizdzz/StringMist/blob/master/jadx.png?raw=true)
![Alt text](https://github.com/wizdzz/StringMist/blob/master/JEB.png?raw=true)
