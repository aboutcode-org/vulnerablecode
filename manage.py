#!/usr/bin/env python

if __name__ == "__main__":
    import site
    site.addsitedir(r"C:\Users\Mohammed Anas\AppData\Roaming\Python\Python314\site-packages")

    from vulnerablecode import command_line

    command_line()
