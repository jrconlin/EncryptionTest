package org.spongycastle.util;

public interface Selector<T>
    extends Cloneable
{
    boolean match(T obj);

    Object clone();
}
