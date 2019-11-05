"""
Created on Jun 09, 2019

@author: Ramakrishna_Thandra
PstesDictonary Class which as getter setter objects to transfer the objects
"""


class PstesDictonary(object):
    def __init__(self):
        super(PstesDictonary, self).__setattr__('internal', {})

    def __setattr__(self, key, value):
        self.internal[key] = value

    def __getattr__(self, key):
        return self.internal[key]

    def __iter__(self):
        return iter(self.internal)

    def values(self):
        return self.internal.values()
