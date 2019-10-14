def:
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o pcap.o pcap.c
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o filter.o filter.c
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o demo.o demo.c
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o test_main.o test_main.c
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o xtest.o xtest.c
	gcc -Wall -o demo demo.o filter.o pcap.o -lgcov
	gcc -Wall -o test xtest.o test_main.o pcap.o filter.o -lgcov

clean: 
	rm -f *.o *.gcda *.gcno *.gcov demo.info
	rm -f *.yml
	rm -rf demo_web
	rm -f demo
	rm -f test

test: def
	./test --fork

check:
	valgrind --leak-check=full -v ./demo

lcov:
	lcov -d ./ -t 'demo' -o 'demo.info' -b . -c
	genhtml -o demo_web demo.info

.PHONY: def clean ut test
