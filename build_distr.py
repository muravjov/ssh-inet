#!/usr/bin/env python3
# coding: utf-8

if __name__ == "__main__":
    import os
    prefix = os.path.dirname(__file__)
    
    with open(os.path.join(prefix, "ssh-inet.py")) as f:
        txt = f.read()
        
    import base64
    with open(os.path.join(prefix, "tornado322.zip"), "rb") as f:
        tornado_zip = base64.b64encode(f.read()).decode("ascii")
    
    import re
    txt = re.sub('''#.*tornado_zip.*=.+$''', 'tornado_zip = "%s"' % tornado_zip, txt, flags=re.M)
    dst_fname = os.path.join(prefix, "distr/ssh-inet")
    with open(dst_fname, "w") as f:
        f.write(txt)
    


