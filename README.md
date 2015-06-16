# JASPIC Experiment
A micro development for a fully functional JASPIC module

This is a JASPIC module that implements servlet form based authentication providing a portable method of authentication. Additionally it provides a passive mechanism for logging out as any redirect starting with ```logout``` would effectively log the user out.

It's currently provided a test case in embedded GlassFish that can be easily launched:
```
$ mvn -P glassfish verify
```
