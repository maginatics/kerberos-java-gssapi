Notes on memory allocation
==========================

Most of the objects used by the Kerberos interface are allocated by library
routines as output parameters. When defining SWIG bindings, there are a couple
of things that we need to bear in mind to support this.

Avoid default constructors
--------------------------

By default, SWIG will handle memory allocation for structures that we parse
in an interface file. For example, if the interface defines a structure

    struct foo_struct {
        int bar;
        int baz;
    };

SWIG will emit a Java class `foo_struct` with the following default constructor:

    public foo_struct() {
        // The first parameter is a pointer to the allocated structure
        // The second parameter indicates that we own this memory
        this(moduleJNI.new_krb5_cred(), true);
    }

This is handy if we want to directly allocate the structure in Java, but for
structures with custom allocators (like most of those in `libkrb5`) it raises
a problem. Consider the following SWIG typemap, which is used to marshall the
type of pointer-to-pointer output parameters commonly used in such methods
(error checking omitted for clarity):

    %typemap(argout) foo_struct ** {
        /* Output argument conversion back into Java foo_struct */
        jclass clazz = (*jenv)->FindClass(jenv, "foo_struct");
        jfileID fid = (*jenv)->GetFileID(jenv, clazz, "swigCPtr", "J");
        (*jenv)->SetLongField(jenv, $input, *$1);
    }

This typemap would be appied to an allocator method such as this:

    int mk_foo(struct foo_struct **out);

The typemap assigns the return value (`*out`) to the internal pointer
(`swigCPtr`) of the Java `foo_struct` object that was passed to it. This
allows us to write Java code like this:

    foo_struct foo = new foo_struct();
    int err = module.mk_foo(foo);

The problem is that if Java has emitted the default constructor, it will have
already allocated memory for a `foo_struct` (using
`malloc(sizeof(foo_struct))`) and stashed it in its internal `swigCPtr`. The
output parameter typemap will leak memory.

To avoid this, we need to prevent generation of the standard constructors and
destructors, and to provide our own, like so:

    %nodefaultctor foo_struct;
    %nodefaultdtor foo_struct;
    %typemap(javacode) struct foo_struct %{
        public foo_struct() {
            this(0, false);
        }
    %}

This prevents memory from being allocated by the `new foo_struct()` in the
Java snippet above, and makes the allocation steps analogous to the familiar
C idiom for such allocations:

    struct foo_struct *foo = NULL;
    int err = mk_foo(&foo);


