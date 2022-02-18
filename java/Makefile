
Main.jar: HelloWorld/Main.class
	jar cfmv Main.jar Manifest.txt HelloWorld/Main.class

HelloWorld/Main.class: HelloWorld/Main.java
	javac HelloWorld/Main.java

run:
	java -jar Main.jar

run2:
	java -cp . HelloWorld.Main

clean:
	-rm Main.jar HelloWorld/Main.class

