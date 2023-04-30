.PHONY: help fuzz-MessageProcessor fuzz-EncodedMessageParser fuzz-Fragment release

help:
	@echo "Make support is limited to functionality that cannot be provided otherwise."
	@echo
	@echo "Goals:"
	@echo "  release: perform release build, disabling extra annotation processors and verifications."
	@echo "  fuzz-MessageProcessor: run afl fuzzer for MessageProcessor"
	@echo "  fuzz-EncodedMessageParser: run afl fuzzer for EncodedMessageParser"
	@echo "  fuzz-Fragment: run afl fuzzer for Fragment"

SOURCE_FILES := $(shell find src/main/java -type f -name '*.java')
target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar: $(SOURCE_FILES)
	mvn clean install -DskipTests

TEST_FILES = $(shell find src/test/java -type f -name '*.java')
target/test-classes: target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar $(TEST_FILES)
	mvn test-compile
	touch target/test-classes

fuzz-MessageProcessor: target/test-classes
	@echo "Checking if AFL_DIR is set and jqf-afl-fuzz binary is available."
	@which jqf-afl-fuzz
	jqf-afl-fuzz -v -c target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar:target/test-classes -i src/test/seeds/MessageParser net.java.otrfuzz.MessageParserDriver fuzzMessage

fuzz-EncodedMessageParser: target/test-classes
	@echo "Checking if AFL_DIR is set and jqf-afl-fuzz binary is available."
	@which jqf-afl-fuzz
	jqf-afl-fuzz -v -c target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar:target/test-classes -i src/test/seeds/EncodedMessageParser net.java.otrfuzz.EncodedMessageParserDriver fuzzMessage

fuzz-Fragment: target/test-classes
	@echo "Checking if AFL_DIR is set and jqf-afl-fuzz binary is available."
	@which jqf-afl-fuzz
	jqf-afl-fuzz -v -c target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar:target/test-classes -i src/test/seeds/Fragment net.java.otrfuzz.FragmentParserDriver fuzzFragment

release:
	mvn -P'!development' clean install

# 'reproducible' requires the current version to be installed. The second build will then be compared to the installed artifact.
# TODO single-assembly creation is not reproducible? (in very least not desirable)
reproducible: release
	mvn -P'!development' clean install artifact:compare -DskipTests

