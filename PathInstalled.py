#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.
"""
This Program is prototype of master thesis toru-tu@naist

Dependes on openflow.discovery
Works with openflow.spanning_tree

"""
from pox.lib.revent import *

class PathInstalled(Event):
    """
    Fired when a path is installed
    """
    def __init__(self,path):
        Event.__init__(self)
        self.path = path

