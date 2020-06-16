package com.wizd.mygradleplugin;

public class ClassStringField {
    public static final String STRING_DESC = "Ljava/lang/String;";

    /* package */ ClassStringField(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String name;
    public String value;
}
