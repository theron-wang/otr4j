/**
 * Definition of the otr4j module.
 */
// TODO `require static` for automatic modules. Ideally, these dependencies define their own module.
module otr4j {
    requires static jsr305;
    requires static com.google.errorprone.annotations;

    requires java.logging;
    requires joldilocks;
    requires org.bouncycastle.provider;
}
