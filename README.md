# SHA1 Length Extension Attack

With this project, I am practicing Length Extension Attack on SHA1. 

A few thing I have been finding out during my work:
* In order to have a better understanding of the attack, I've built my own SHA1 generator. Actually, building SHA1 generator (or at least a part it) is required for implementation of the attack
* You have to known exactly the length of secret key to get the attack working. In reality, I think, this could be worked out using brute force. In my example, I made an assumption that the key length was already present (likes almost all SHA1 Length Extension Attack examples out there :P). 
* I had quite hard time trying to figure out how to deal with added HEX string value to the message. I guess, the way server handles these HEX string might affect the attack, and mostly negatively. If a server would consider HEX string "\x80" e.g. as four single characters and not as a HEX value, then the Attack data might be failed calculated. Or am I missing something here?
