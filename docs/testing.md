# Testing

Notes on testing and mocking best practices.

## Mocking caveats

- For verification of method calls after execution, make sure that you use: `verify(someObject).myFunction(isA(String.class));`  
  That is, use `isA` to match types, instead of `any`. `any` only works for `when(...)` calls in mocks, but silently succeeds if used incorrectly. (See `StateExpect3Test.java` for an example.)
