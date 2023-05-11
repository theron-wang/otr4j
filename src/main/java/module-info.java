/**
 * Definition of the otr4j module.
 */
module otr4j {
    // FIXME `jsr305` is filename-based module declaration, should not be published to public repository.
    requires static jsr305;
    // FIXME `com.google.errorprone.annotations` is filename-based module declaration, should not be published to public repository.
    requires static com.google.errorprone.annotations;

    requires java.logging;
    requires joldilocks;
    requires org.bouncycastle.provider;
}
