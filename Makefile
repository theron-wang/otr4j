.PHONY: help run-afl

help:
	@echo "Make support is limited to functionality that cannot be provided otherwise."
	@echo
	@echo "Goals:"
	@echo "  run-afl: run afl fuzzer"

SOURCE_FILES := $(shell find src/main/java -type f -name '*.java')
target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar: $(SOURCE_FILES)
	mvn clean install -DskipTests

TEST_FILES = $(shell find src/test/java -type f -name '*.java')
target/test-classes: target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar $(TEST_FILES)
	mvn test-compile
	touch target/test-classes

run-afl: target/test-classes
	# See https://github.com/rohanpadhye/jqf/wiki/Fuzzing-with-AFL for more information.
	@echo 'Running afl through JQF. (https://github.com/rohanpadhye/jqf)'
	@echo "Checking if AFL_DIR is set and jqf-afl-fuzz binary is available."
	@which jqf-afl-fuzz
	jqf-afl-fuzz -v -c target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar:target/test-classes -i src/test/fuzzing-seeds net.java.otrfuzz.MessageParserDriver fuzzMessage
