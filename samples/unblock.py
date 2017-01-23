#!/usr/bin/env python

#   Copyright (C) 2006-2014 Ludovic Rousseau <ludovic.rousseau@free.fr>
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

from __future__ import print_function

import PyKCS11

pin = "1234"
puk = "1234"

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load()
slot = pkcs11.getSlotList()[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_RW_SESSION)
session.login(puk, PyKCS11.CKU_SO)
session.initPin(pin)
session.logout()
session.closeSession()
