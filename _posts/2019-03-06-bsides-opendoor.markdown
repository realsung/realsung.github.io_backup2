---
title: "BSides CTF 2019 - opendoor"
date: 2019-03-06
categories: [reversing, ctf]
tags: [reversing]
---

<!--more-->

This one is a pretty interesting challenge. I've used IDA Free only.  
But before jumping into **main**, I'll be analyzing the **opendoor** namespace

![buffer_const](/images/bsides/buffer_constr.png)

So, the class **Buffer** has two members; a vector of bytes and a offset indicating where to start the next read

```cpp
namespace opendoor {
    class Buffer {
        shared_ptr<vector<byte>> m_buffer;
        int m_offset;
    public:
        Buffer() {
            m_buffer = make_shared(vector<byte>);
            m_offset = 0;
        }
        // ...
    };
};
```

Now lets analyze the **Buffer::read\<T\>** functions. This is important as it tells how the server unmarshalls the data.  
**Buffer::read\<bool\>** is a wrapper to **Buffer::read\<uchar\>**.  
Int32 and Int64 are being read in **BigEndian**

![read_long](/images/bsides/read_long.png)

i.e., var_20[7 - var_14] = Buffer::read\<uchar\>()

**read\<shared_ptr\<vector\<uchar\>\>\>** and **read\<string\>** work the same. The first call **read\<uint\>** to read the no. of. bytes and **read\<uchar\>** to read that many bytes i.e., a vector is a string of bytes prefixed by its length

![aes_const](/images/bsides/aes_crypter_constr.png)

The constructor of **AESCrypter** calls the superclass constructor, before initializing the members. **AESCrypter::decrypt** and **AESCrypter::encrypt** perform decryption and encryption using AES 256 CBC.

```cpp
namespace opendoor {
    class Crypter {
    public:
        virtual void decrypt(shared_ptr<Buffer>) = 0;
        virtual void encrypt(shared_ptr<Buffer>) = 0;
    };

    class AESCrypter : public Crypter {
        char* key;
        char* iv;
    public:
        AESCrypter() {
            key = opendoor::def_key;
            iv = opendoor::def_iv;
        }
        AESCrypter(char* k, char* i) {
            key = k; iv = i;
        }
        void* decrypt(shared_ptr<Buffer> p) {
            buf = _Decrypt(*p, key, iv);
            return make_shared<Buffer>(buf);
        }
        void* encrypt(shared_ptr<Buffer> p) {
            buf = _Encrypt(*p, key, iv);
            ans = make_shared<Buffer>();
            ans->write(buf.size());
            ans->write(buf);
            return ans;
        }
    };
};
```

There is another class that implements **Crypter**. Its the **PlainCrypter**. Well you have guessed it right. Its a dummy class which neither encrypts nor decrypts. It has another parameter which if set to TRUE, prints debug logs.

Let's move to **opendoor::State** which encapsulates a lock for the magic door.

![state_const](/images/bsides/state_constr.png)

The methods of **State** are straightforward. Here's the representation of **State**

```cpp
namespace opendoor {
    class State {
        byte m_is_unlocked;
        byte m_is_debuggable;
        int32 m_unlock_count;
        int64 m_door_id;
    public:
        State() {
            m_is_unlocked = m_is_debuggable = 0;
            m_unlock_count = 0;
            m_door_id = 0x55AA55AA5A5AA5A5;
        }
        void unlock() {
            m_is_unlocked = 1;
            m_unlock_count++;
        }
        void lock() {
            m_is_unlocked = 0;
        }
        // getters ...
    };
};
```

## The Messaging Protocol

The **Message** class consists of six methods - **parse_message**, **execute**, **to_string**, **serialize**, **ptr**, and **get_id** out of which **parse_message**, **to_string** and **get_id** are pure virtual, i.e., they have to be implemented in the classes implementing **Message**.  

The subclasses of **Message** are of:

1.  Messages that have a request and response - **UnlockMessage**, **DebugMessage**, **PingMessage**
2.  **ErrorMessage**

**Message::serialize** performs the common serialization.  
It writes the *message_id* followed by the *timestamp* returned by **time()**.

Now let's go to **Message::ParseMessage**

![msg_parse_msg](/images/bsides/msg_parse_msg.png)

It reads two Int32 words i.e., the **message_id** and **timestamp** and checks if the recieved timestamp bounded by **5 seconds** of the current timestamp. Otherwise it responds with an **INVALID_TIMESTAMP** ErrorMessage. I'll discuss later how I got error constant names.

The generic parsing routine

```cpp
ParseMessage(shared_ptr<Buffer> p)
{
    msg_id = p->read();
    msg_stamp = p->read();
    
    // time_in_window(a, b) == return abs(time(NULL)-a) <= b
    
    if (! time_in_window(msg_stamp, 5))
    {
        err = new ErrorMessage(INVALID_TIMESTAMP);
        return err->ptr();
    }
    f = messages_map.find(msg_id)
    if (f == messages_map.end())
    {
        err = new ErrorMessage(INVALID_MESSAGE);
        return err->ptr();
    }
    msg = (f->second)();

    // do message specific parse
    if (! msg->parse_message(p))
    {
        err = new ErrorMessage(INVALID_PARSE);
        return err->ptr();
    }
}
```

So, the timestamp must be within 5 seconds.

**Message** also defines 7 lambdas that creates an instance each of the concrete message classes and encapsulates within a **shared_ptr**.

### 1. UnlockMessage

**UnlockMessage::parse_message** reads two Int64 words and stores them in its member variables.

![unlock_exec](/images/bsides/unlock_exec.png)

Clearly, the first member variable must be non zero and the second member variable must equate to **door_number**. The _good branch continues at

![unlock_exec_2](/images/bsides/unlock_exec_2.png)

which unlocks the door and creates an **UnlockResponse**. While the _bad branch, locks the door instead and returns an ACCESS\_DENIED **ErrorMessage**.

Now we can represent **Message** as

```c
struct Message
{
    int32_t id;
    int32_t time_stamp;
    union {
        union {
            UnlockMessage uMsg;
            DebugMessage dMsg;
            PingMessage pMsg;
        } msg;
        ErrorMessage eMsg;
    };
};

struct UnlockMessage
{
    int64_t do_unlock;
    int64_t door_no;
};
```

### 2. DebugMessage

**DebugRequestMessage::parse_message**:

![debug_parse](/images/bsides/debug_parse.png)

It reads an Int32 which can be either 1 or 2. If the value read is 1, then it reads a boolean. If the value is 2, it reads a string. These are stored in member variables at offsets +8, +12, +16

**DebugRequestMessage::execute**:

![debug_exec](/images/bsides/debug_exec.png)

If the member at offset +8 is 1 then **DebugRequestMessage::handle_debug_message_** is called. If the value is not 1 and the lock is not debuggable, an **ACCESS\_DENIED** Error is returned. Whereas if the value is 2, and the lock is debuggable, **DebugRequestMessage::handle_readfile** is called.

Thus the member at offset +8, denotes the *debug_type*

Yay ! This looks promising !

So, to execute **handle_readfile_**, we must have the lock's **DEBUG** flag turned on. But the lock's debug flag is initially 0.

**handle_debug_message_**:

![debug_handle_dbg](/images/bsides/debug_handle_dbg.png)

If the member at offset +12 is 1, the routine turns on the door's **DEBUG** flag if the door is unlocked. If the value at offset +12 is not 1, then the door's debug flag is turned off.

The member at offset +12 denotes the flag for turning on lock's debug flag.

**handle_readfile_** reads 4K bytes from the file whose path is stored in the member variable at offset +16 and returns the contents.

```c
struct DebugMessage
{
    int32_t debug_type;
    int8_t b_debug_lock;
    std::string filePath;
};
```

## Approach

1. Send **UnlockMessage** to set the lock's status to **UNLOCKED**
2. Send **DebugMessage** of type 1 to set the lock's **DEBUG** flag
3. Send **DebugMessage** of type 2 to read any file !!

The **ConnectionPool** class uses non-blocking IO. It maintains a map whose keys are the client socket descriptors and values are instances of **ConnectionHandler**. The **do_read_** (**do_write**) methods read (write) a vector of bytes (from the socket) in the same format as **Buffer** reads (writes).

Here's the vtable for **ConnectionHandler**

![conn_handlr_vtbl](/images/bsides/conn_handler_vtable.png)

The members of **ConnectionHandler** are

```cpp
namespace opendoor {
    class ConnectionHandler {
        int32_t socket;                 /* +0x8 */
        bool b_closed;                  /* +0xC */
        int32_t read_size;              /* +0x10 */
        vector<byte> write_vec;         /* +0x18 */
        vector<byte> read_vec;          /* +0x30 */
        shared_ptr<Buffer> buffer;      /* +0x48 */
        shared_ptr<State> lock;         /* +0x58 */
        shared_ptr<Crypter> cryptr;     /* +0x68 */
        // ...
    };
}
```

Let's visit **ConnectionHandler::process_message_**

![conn_proc](/images/bsides/conn_proc.png)

The routine calls **cryptr->decrypt()** on **buffer**. If the decryption is successful, it proceeds to **ParseMessage**

![conn_proc_2](/images/bsides/conn_proc_2.png)

If the message has been parsed successfully, the **execute()** method is invoked. If it succeeds, a positive response is returned by invoking **serialize()** followed by **cryptr->encrypt()**

Last but not the least, **init**

![init](/images/bsides/init.png)

The second routine, sets up the **map**s as follows

```python
messages = {
# opendoor::Message::{lambda(void)#i}::operator()
    1  : 0x48900,    # PingRequest
    2  : 0x48940,    # PingResponse
    3  : 0x48980,    # UnlockRequest
    4  : 0x489C0,    # UnlockResponse
    5  : 0x48A00,    # DebugRequest
    6  : 0x48A40,    # DebugResponse
    -1 : 0x48A80     # ErrorMessage
}

error_messages = {
    0     : "Unknown",
    1     : "Invalid Message Type",
    2     : "Invalid Timestamp",
    3     : "Error Parsing",
    4     : "Crypto Error",
    0x193 : "Access Denied",
    0x194 : "Resource Not Found"
}
```

**main** is also straightforward. It calls **parse_flags** to determine the default **Crypter** instance to be used. The default is **AESCrypter**. If **-n** is specified, **PlainCrypter** is used. The default port is 4848 which can be changed with **-p** option.

So, we have to write the encrypted **Message** prefixed by the size of the encrypted message to the server.

## Source Code

```python
#!/usr/bin/python

from Crypto.Cipher import AES
from pwn import *

PLAINTEXT = 0

def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

door_number = 0x55AA55AA5A5AA5A5
key = '\x97\x8B\x8B\x8F\x8C\xC5\xD0\xD0\x88\x88\x88\xD1\x8C\x86\x8C\x8B\x9A\x92\x90\x89\x9A\x8D\x93\x90\x8D\x9B\xD1\x9C\x90\x92\xD0\xFF'
iv = 'notaflagnotaflag'

def encrypt(msg):
    aes = AES.new(key=key, IV=iv, mode=AES.MODE_CBC)
    ans = aes.encrypt(pad(msg))
    del aes
    return ans

def decrypt(msg):
    aes = AES.new(key=key, IV=iv, mode=AES.MODE_CBC)
    ans = aes.decrypt(msg)
    del aes
    return unpad(ans)

def i32(i):
    return p32(i, endian='big')

def i64(i):
    return p64(i, endian='big')

def pStr(s):
    return i32(len(s)) + s

def debugReq1(f):
    return i32(1) + chr(f)

def debugReq2(f):
    return i32(2) + pStr(f)

def unlockReq():
    return i64(1) + i64(door_number)

def msg(msg_id, oMsg):
    body = i32(msg_id) + i32(int(time.time()+2)) + oMsg
    if not PLAINTEXT:
        body = encrypt(body)
    m = i32(len(body)) + body
    return m

def parse(msg):
    size = u32(msg[:4], endian='big')
    print "[*] Message size: %d bytes" % size
    msg = msg[4:4+size]
    if not PLAINTEXT:
        msg = decrypt(msg)
    msg_id = u32(msg[:4], endian='big')
    print "[*] Message ID: %d" % msg_id
    time_stamp = u32(msg[4:8], endian='big')
    print "[*] Timestamp: %d" % time_stamp
    if msg_id == 4:
        uflag = u64(msg[8:16], endian='big')
        door = u64(msg[16:24], endian='big')
        print "[ Unlock ] - [ unlock_flag : %d, door_num : %x ]" % (uflag, door)
    elif msg_id == 6:
        debug_option = u32(msg[8:12], endian='big')
        if debug_option == 1:
            print "[ Debug ] - [ debug_flag : %d ]" % ord(msg[12])
        else:
            size = u32(msg[12:16], endian='big')
            text = msg[16:16+size]
            print "[ Debug ] - [ text : '%s' ]" % text


r = remote('opendoor-ea62dae9.challenges.bsidessf.net', 4141)

# unlock request to set unlock flag
# send debug request with debug flag on to debug
# send debug request to read any file

r.send(msg(3, unlockReq()))
parse(r.recv())
r.send(msg(5, debugReq1(1)))
parse(r.recv())
r.send(msg(5, debugReq2('/home/opendoor/flag.txt')))
parse(r.recv())
r.close()
```

And the Output ...

![output](/images/bsides/output.png)

    Solved after the CTF was over :(
