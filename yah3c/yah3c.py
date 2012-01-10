#!/usr/bin/env python
# -*- coding:utf-8 -*-
""" Main program for YaH3C.

"""

__version__ = '0.1'

import os, sys, subprocess
import ConfigParser
import getpass
from argparse import ArgumentParser
from socket import *
from time import ctime

import eapauth
import usermanager
            
def prompt_user_info():
    name = raw_input('Input user name: ')
    while True:
        password = getpass.getpass('Input password: ')
        password_again = getpass.getpass('Input again:: ')
        if password == password_again: break
        else: print 'Password do not match!'
    dev = raw_input('Device(eth0 by default): ')
    if not dev: dev = 'eth0'
    return name, password, dev

def parse_options():
    opts = []
    parser = ArgumentParser(prog='yah3c')
    parser.add_argument('-c', const=True, action='store_const', help='choose a user')
    parser.add_argument('-a', const=True, action='store_const', help='create a new user')

    return parser, parser.parse_args(sys.argv[1:])

def is_single():
    p = subprocess.Popen('ps -e|grep yah3c', shell=True, stdout=subprocess.PIPE)
    p.wait()
    r = p.stdout.readlines()
    if len(r) > 1:
        print 'An instance of yah3c is running.'
        return False
    else:
        return True

def main():
    # parse the options from argv
    ps, opts = parse_options()

    if 'h' in opts or 'help' in opts:
        ps.print_help()
        return
        
    # check for root privilege
    if not (os.getuid() == 0):
        print ('亲，要加sudo!')
        exit(-1)

    if not is_single():
        exit(1);

    # collect login info
    um = usermanager.UserManager()
    login_info = []
    if um.get_user_number() == 0:
        choice = raw_input('No user conf file found, creat a new one?\n<Y/N>: ')
        if choice in ('y', 'Y'):
            um.create_user(prompt_user_info())

    users_info = um.get_users_info()
    if opts.a:
        try:
            login_info = prompt_user_info()
            um.create_user(login_info)
        except ConfigParser.DuplicateSectionError:
            print 'user already exist!'
    elif opts.c: 
        for i, u in enumerate(users_info):
            print i, u

        while True:
            try:
                choice = int(raw_input('Your choice: '))
                if choice >= len(users_info):
                    raise ValueError
            except ValueError:
                print 'Please input a valid number!'
            else: break;

        login_info = um.get_user_info(choice)
    else:
        login_info = um.get_user_info(0)

    # begin authorize
    yah3c = eapauth.EAPAuth(login_info)
    yah3c.serve_forever()

if __name__ == "__main__":
    main()
