package com.yuandaima;

import com.yuandaima.IHelloCallback;
import com.yuandaima.MyStruct;
import com.yuandaima.MultiString;

interface IHello {
    void hello();
    int sum(int x, int y);
    void waitAndCallback(int seconds, IHelloCallback callback);
    void printStruct(in MyStruct data);
    void sendMultistring(in MultiString multiStr);
    void diverseArgs(int arg1, long arg2, float arg3, double arg4, boolean arg5, String arg6, String arg7, in int[] arg8);
    void testFD(in FileDescriptor fd);
    void testArrayOfStrings(in String[] strings);
    void testArrayOfBinders(in IHelloCallback[] callbacks);
}