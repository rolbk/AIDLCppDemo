package com.yuandaima;

import com.yuandaima.IHelloCallback;
import com.yuandaima.MyStruct;

interface IHello {
    void hello();
    int sum(int x, int y);
    void waitAndCallback(int seconds, IHelloCallback callback);
    void printStruct(in MyStruct data);
}
