# Name :emoji:

## Description: 

* Only authenticated users may pass!

## Objective: 

* Basic Reverse Engineering

## Flag: :black_flag:
* UNIWA{b4by_r3v_r3v3rs3d}

## Challenge:

This challenge is beginner friendly, for people who just started RE challenges.

We start with a `file`: 

```sh
$ file babyrev
babyrev: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ea35a477600cd39b8a773dab2d86ad600c79745c, stripped
```

The binary is `stripped` that means we have no names of the functions. 

The interface looks like this:

```sh
w3th4nds@void:~/github/UNIWA_CTF_2020-2021/rev/babyrev$ ./babyrev 
--Authentication--
Username: username
```

That means we need some kind of credentials.

Let's open a disassembler to get a better view of the code.

### Disassembly :pick:

We start from `entry`:

```c
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(FUN_00100980,in_stack_00000000,&stack0x00000008,FUN_00100aa0,FUN_00100b10,
                    param_3,auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

As we can see it calls `FUN_00100980()`.

Let's call this `main()`.

So now, inside `main()`:

```c
void main(void)

{
  int iVar1;
  int in_EDI;
  long in_FS_OFFSET;
  char local_48 [32];
  char local_28 [24];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  memset(local_28,0,0x11);
  if (1 < in_EDI) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fwrite("--Authentication--\nUsername: ",1,0x1d,stderr);
  fgets(local_48,0x14,stdin);
  iVar1 = strncmp(local_48,"w3t",3);
  if (iVar1 == 0) {
    fwrite("Password: ",1,10,stderr);
    fgets(local_28,0x14,stdin);
    iVar1 = strncmp(local_28,"d3sr3v3r_v3r_yb4b",0x11);
    if (iVar1 == 0) {
      FUN_001008da();
    }
    else {
      puts(&DAT_00100b7e);
    }
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

There are  2 comparisons:

* Username == "w3t"
* Password == "d3sr3v3r_v3r_yb4b"

After that, it calls `FUN_001008da()`.

```c
void FUN_001008da(void)

{
  long lVar1;
  long in_FS_OFFSET;
  int local_14;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fwrite("\nFlag: UNIWA{",1,0xd,stderr);
  local_14 = 0x11;
  while (-1 < local_14) {
    fputc((int)(char)(&DAT_00100b3f)[local_14],stderr);
    local_14 = local_14 + -1;
  }
  fwrite("}\nGood job!\n",1,0xc,stderr);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This function prints the flag. 

There is a while loop which just takes whatever there is at `DAT_00100b3f` and reverse it.

The password is stored at this location so it just prints `d3sr3v3r_v3r_yb4b` in reverse order.

We can just input the username and password and let the program do the rest.

### PoC: :checkered_flag:

```sh
w3th4nds@void:~/github/UNIWA_CTF_2020-2021/rev/babyrev$ ./babyrev 
--Authentication--
Username: w3t
Password: d3sr3v3r_v3r_yb4b

Flag: UNIWA{b4by_r3v_r3v3rs3d}
Good job!
```

