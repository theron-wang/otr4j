public class Issue347 {
    static class ReadInsideAssert {
        Object f;
    
        public ReadInsideAssert(Object o) {
          this.f = o;
          if (this.f.toString() != "") throw new Error();
          assert this.f.toString() != "";
        }
    }
}
