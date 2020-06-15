# StringMist
Gradle plugin for encrypt string constant on Java<br>

The plugin seems like [StringFog](https://github.com/MegatronKing/StringFog), but I have added some thing interesting.<br>
(Actually there are some code I just copy from StringFog directly.)<br>

## Funny stuff
This plugin generate a strDec method for every Java class for prevent the reverse engineer hook the only strDec method on the original plugin conveniently.<br>
If do so, he will get the ciphertext and plaintext easily, I think that is pretty ... weak, not bring an enough challenge for the hacker, and it will be decrypted automatically on new version of JEB.<br>
So, think about that, generate hooking code for every different class and different method, seems like shitty and disgusting, right ?<br>

## Something that not perfect on original plugin
During plagiarism code from StringFog, I have found that it will replace some empty string("") with null.<br>
That's not right and will cause some exceptions, maybe I just use his code with wrong approach, anyway, I fixed it on my code.
