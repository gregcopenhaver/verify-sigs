#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from verifysigs.utils import Fingerprinter, FormatResults, FindPehash


def main(filenames):
    for filename in filenames:
        print('Scanning %s' % filename)
        with open(filename, 'rb') as file_obj:
            fingerprinter = Fingerprinter(file_obj)
            is_pecoff = fingerprinter.EvalPecoff()
            fingerprinter.EvalGeneric()
            results = fingerprinter.HashIt()
            print(FormatResults(file_obj, results))
            if is_pecoff:
                FindPehash(results)


if __name__ == '__main__':
    main(sys.argv[1:])
