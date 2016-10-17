#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#  IDAtropy
#  22/05/2015
#
#  Daniel Garcia <danigargu [at] gmail.com>
#  @danigargu
# 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.
#

import math
import sys
import time
import string

from idc import *
from idaapi import *
from idautils import *
from sets import Set

# IDA < 6.9 support
if IDA_SDK_VERSION < 690:
  from PySide import QtGui, QtCore
  from PySide.QtGui import QTextEdit, QTableWidget, QTreeWidget, QCheckBox
  QtWidgets = QtGui
  USE_PYQT5 = False
else:
  from PyQt5 import QtGui, QtCore, QtWidgets
  from PyQt5.QtWidgets import QTextEdit, QTableWidget, QTreeWidget, QCheckBox
  USE_PYQT5 = True

try:
  import matplotlib.pyplot as plt
  import matplotlib.ticker as ticker

  if USE_PYQT5:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
  else:
    from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.backends.backend_qt4agg import NavigationToolbar2QT as NavigationToolbar
  from matplotlib.backend_bases import key_press_handler  
except ImportError:
  ERROR_MATPLOTLIB = True

PLUG_NAME    = "IDAtropy"
PLUG_VERSION = "v0.1"

def log(msg):
  Message("[%s] %s\n" % (PLUG_NAME, msg))

def histogram(data):
  table = [0]*256
  for i in map(ord, data):
    table[i] += 1
  return table

def entropy_scan(data, block_size=256):
  for block in (data[i:i+block_size] for i in xrange(0, len(data), block_size)):
    yield entropy(block)

# byte precision
def deep_entropy_scan(data, block_size=256):
  for block in (data[x:block_size+x] for x in range(len(data) - block_size)):
    yield entropy(block)

def entropy(data):
  if not data:
    return 0
  entropy = 0
  for x in range(256):
    p_x = float(data.count(chr(x)))/len(data)
    if p_x > 0:
      entropy += - p_x*math.log(p_x, 2)
  return entropy

def get_ida_bytes(start_addr, end_addr, debug_memory):
  bytes = ""
  read_byte = Byte
  if debug_memory:
    read_byte = DbgByte

  try:
    # Another more efficient way to prevent section size aligment in IDB?
    c_addr = start_addr
    while c_addr < end_addr:
      if isLoaded(c_addr):
        bytes += chr(read_byte(c_addr))
      c_addr += 1

  except Exception, e:
    warning("Error reading data: %s" % e)
    return None
  return bytes 

def get_data(config):
  data = ""
  if config.disk_binary:
    with open(GetInputFilePath(), 'rb') as f:
      data = f.read()
  else:
    data = get_ida_bytes(config.start_addr, config.end_addr, config.debug_memory)
  if data:
    return data
  return None

class Config:
  def __init__(self):
    self.chart_type   = 0
    self.start_addr   = 0
    self.end_addr     = 0
    self.chart_type   = 0
    self.block_size   = 256
    self.disk_binary  = False
    self.debug_memory = False
    self.byte_entropy = False
    self.chart_types  = ["Histogram", "Entropy"]

class ChartType:
  HISTOGRAM = 0
  ENTROPY   = 1

class Options(QtWidgets.QWidget):
  def __init__(self, parent):
    QtWidgets.QWidget.__init__(self)
    self.parent = parent
    self.config = parent.config
    self.name = "Options"
    self.create_gui()

  def chart_type_on_click(self):
    if not self.update_addrs():
      warning("Invalid address")
      return
    try:
      show_wait_box("Making chart...")
      data = get_data(self.config)
      if not data:
        hide_wait_box()
        warning("There's no data to make the chart")
        return
      if self.config.chart_type == ChartType.ENTROPY:       
        self.parent.tabs.addTab(Entropy(self, data), self.get_tab_title())
      elif self.config.chart_type == ChartType.HISTOGRAM:
        self.parent.tabs.addTab(Histogram(self, data), self.get_tab_title())
      del data
    except Exception, e:
      warning("%s" % e)
    hide_wait_box()    

  def get_tab_title(self):
    i_type = self.config.chart_type
    title = self.config.chart_types[i_type] + " - "
    if self.config.disk_binary:
      title += "Disk binary"
    else:
      segname = SegName(self.config.start_addr)
      if segname:
        title += "%s " % segname
      title += "[0x%08x - 0x%08x]" % (self.config.start_addr, self.config.end_addr)
    return title

  def create_gui(self):
    self.t_start_addr    = QtWidgets.QLineEdit(self)
    self.t_end_addr      = QtWidgets.QLineEdit(self)
    self.cb_section      = QtWidgets.QComboBox(self)
    self.cb_disk_bin     = QtWidgets.QCheckBox(self)
    self.cb_debug_memory = QtWidgets.QCheckBox(self)
    button_chart         = QtWidgets.QPushButton("Chart")

    self.t_start_addr.setFixedWidth(200)
    self.t_end_addr.setFixedWidth(200)
    self.cb_section.setFixedWidth(200)
    button_chart.setFixedWidth(50)

    self.fill_sections()

    form = QtWidgets.QFormLayout()
    form.addRow("Start address:", self.t_start_addr)
    form.addRow("End address:", self.t_end_addr)
    form.addRow("Section:", self.cb_section)
    form.addRow("Disk binary:", self.cb_disk_bin)
    form.addRow("Debug memory:", self.cb_debug_memory)
    form.addRow("Chart type:", self.create_chart_type_group())
    form.addRow(button_chart)

    self.cb_section.currentIndexChanged[int].connect(self.cb_section_changed)
    self.cb_disk_bin.stateChanged.connect(self.cb_changed)
    self.cb_debug_memory.toggled.connect(self.cb_changed)
    button_chart.clicked.connect(self.chart_type_on_click)

    self.setLayout(form)

  def cb_changed(self, state):
    sender = self.sender()

    if sender is self.cb_disk_bin:    
      checked = (state == QtCore.Qt.Checked)  
      self.config.disk_binary = checked
      b_enabled = not checked

      self.t_start_addr.setEnabled(b_enabled)
      self.t_end_addr.setEnabled(b_enabled)
      self.cb_section.setEnabled(b_enabled)
      self.cb_debug_memory.setEnabled(b_enabled)

    elif sender is self.cb_debug_memory:
      if idaapi.is_debugger_on():
        self.config.debug_memory = state
      else:
        warning("The debugger is not running")
        block = sender.blockSignals(True)
        sender.setChecked(False)
        sender.blockSignals(block)

  def is_not_xtrn_seg(self, s_ea):
    if GetSegmentAttr(s_ea, SEGATTR_TYPE) != SEG_XTRN:
      return True
    return False
    
  def fill_sections(self):
    segments = filter(self.is_not_xtrn_seg, Segments()) 

    for idx, s_ea in enumerate(segments):
      if idx == 0:
        self.set_addrs(SegStart(s_ea), SegEnd(s_ea))
      self.cb_section.addItem(SegName(s_ea), s_ea)

    if not segments:
      self.set_addrs(0 ,0)
      self.cb_section.setEnabled(False)

  def create_chart_type_group(self):
    vbox = QtWidgets.QVBoxLayout()
    self.rg_chart_type = QtWidgets.QButtonGroup()
    self.rg_chart_type.setExclusive(True)

    for i, choice in enumerate(self.config.chart_types):
      radio = QtWidgets.QRadioButton(choice)
      self.rg_chart_type.addButton(radio, i)
      if i == self.config.chart_type: 
        radio.setChecked(True)
      vbox.addWidget(radio)

    vbox.addStretch(1)
    self.rg_chart_type.buttonClicked.connect(self.bg_graph_type_changed)
    return vbox

  def bg_graph_type_changed(self, radio):
    self.config.chart_type = self.rg_chart_type.checkedId()

  def cb_section_changed(self, value):
    sender = self.sender()
    s_ea = sender.itemData(value)
    start_addr = SegStart(s_ea)
    end_addr   = SegEnd(s_ea)
    self.set_addrs(start_addr, end_addr)

  def set_addrs(self, start_addr, end_addr):
    self.t_start_addr.setText("0x%x" % start_addr)
    self.t_end_addr.setText("0x%x" % end_addr)
    self.config.start_addr = start_addr
    self.config.end_addr = end_addr

  def update_addrs(self):
    try:
      self.config.start_addr = int(self.t_start_addr.text(), 16)
      self.config.end_addr   = int(self.t_end_addr.text(), 16)
      return True
    except ValueError:
      return False

class Entropy(QtWidgets.QWidget):
  def __init__(self, parent, data):
    QtWidgets.QWidget.__init__(self)
    self.parent = parent
    self.config = parent.config
    self.data   = data
    self.gen_entropy_chart()

  def gen_entropy_chart(self):
    blocks = len(self.data)/self.config.block_size
    results = list(entropy_scan(self.data))
    min_value, max_value  = min(results), max(results)
    avg_values = sum(results) / len(results)

    self.fig = plt.figure(facecolor='white')
    ax = plt.subplot(111, axisbg='white')
    ax.axis([0, blocks, 0, 8])
    plt.plot(results, color="#2E9AFE")    

    log("Entropy - Start address: 0x%08x" % self.config.start_addr)
    log("Entropy - End address:   0x%08x" % self.config.end_addr)
    log("Entropy - Data size: %d bytes (blocks: %d)" % (len(self.data), blocks))
    info_str = 'Entropy - Min: %.2f | Max:  %.2f | Avg: %.2f' % (min_value, max_value, avg_values)
    log(info_str)
    del self.data

    plt.xlabel('Byte range')
    plt.ylabel('Entropy')
    plt.title('Entropy levels')

    self.canvas = FigureCanvas(self.fig)
    self.toolbar = NavigationToolbar(self.canvas, self)
    self.line_edit = QtWidgets.QLineEdit()

    grid = QtWidgets.QGridLayout()
    grid.setSpacing(10)

    self.cb_jump_on_click = QtWidgets.QCheckBox("Disable double-click event")    
    self.cb_jump_on_click.stateChanged.connect(self.disable_jump_on_click)
    grid.addWidget(self.canvas, 0, 0)
    grid.addWidget(self.toolbar, 1, 0)

    if not self.config.disk_binary:
      grid.addWidget(self.cb_jump_on_click, 2, 0)
      self.cid = self.fig.canvas.mpl_connect('button_press_event', self.on_click)
    self.setLayout(grid)

  def disable_jump_on_click(self, state):
    if state == QtCore.Qt.Checked:
      self.fig.canvas.mpl_disconnect(self.cid)
    else:
      self.cid = self.fig.canvas.mpl_connect('button_press_event', self.on_click)

  def on_click(self, event):
    if event.dblclick and event.xdata:
      addr = self.config.start_addr + (int(event.xdata) * self.config.block_size)
      log("Pressed addr: 0x%08x" % addr)
      try:
        idc.Jump(addr)
      except:
        log(traceback.format_exc())

class TableItem(QtWidgets.QTableWidgetItem):  
  class ItemType:
    DEC = 0
    HEX = 1
    FLOAT = 2
    TEXT = 3

  def __init__(self, text, item_type):
    QtWidgets.QTableWidgetItem.__init__(self, text, QtWidgets.QTableWidgetItem.UserType)
    self.setFlags(QtCore.Qt.ItemIsEnabled)
    self.item_type = item_type
    self.text = text  

  def __lt__(self, other):
    if self.item_type == self.ItemType.DEC:
      return int(self.text) < int(other.text)
    elif self.item_type == self.ItemType.HEX:
      return int(self.text, 16) < int(other.text, 16)
    elif self.item_type == self.ItemType.FLOAT:
      data = float(self.text.replace("%", ""))
      other_data = float(other.text.replace("%", ""))
      return data < other_data
    elif self.item_type == self.ItemType.TEXT:
      return self.text < other.text
    else:
      raise TypeError("The ItemType specified is not supported")

class Histogram(QtWidgets.QWidget):
  def __init__(self, parent, data):
    QtWidgets.QWidget.__init__(self)
    self.parent = parent
    self.config = parent.config
    self.data   = data
    self.gen_histogram()

  def gen_histogram(self):
    grid = QtWidgets.QGridLayout()
    self.data_size = len(self.data)
    self.counter   = histogram(self.data)
    self.counts    = [round(100*float(byte_count)/self.data_size, 2) for byte_count in self.counter] 
    top_y          = math.ceil(max(self.counts)*10.0)/10.0
    del self.data

    self.create_table()
    fig = plt.figure(facecolor='white', figsize=(7,3))
    ax = plt.subplot(111, axisbg='white')

    control_bytes    = 0
    whitespace_bytes = 0
    null_bytes       = self.counter[0]
    printable_bytes  = sum([self.counter[byte] for byte in range(0x21, 0x7F)])
    high_bytes       = sum([self.counter[byte] for byte in range(0x80, 0x100)])

    for byte in range(1, 0x21):
      if chr(byte) in string.whitespace:
        whitespace_bytes += self.counter[byte]
      else:
        control_bytes += self.counter[byte]

    log("Histogram - Data size: %d bytes" % self.data_size)
    self.log_byte_stats("NULL bytes", null_bytes)
    self.log_byte_stats("Control bytes", control_bytes)
    self.log_byte_stats("Whitespace bytes", whitespace_bytes)
    self.log_byte_stats("Printable bytes", printable_bytes)
    self.log_byte_stats("High bytes", high_bytes)

    plt.axis([0, 256, 0, top_y])
    ax.bar(range(256), self.counts, width=1, color="#2E9AFE")

    plt.title("Byte histogram")
    plt.xlabel('Byte range')
    plt.ylabel('Occurance [%]')

    self.canvas  = FigureCanvas(fig)
    self.toolbar = NavigationToolbar(self.canvas, self)
    grid.addWidget(self.canvas, 0, 0)
    grid.addWidget(self.toolbar, 1, 0)
    grid.addWidget(self.table, 0, 1, 0, 2)
    self.setLayout(grid)

  def log_byte_stats(self, name, n_bytes):
    log("Histogram - %-18s: %6d (%2.02f %%)" % (name, n_bytes, (float(n_bytes)/self.data_size*100)))

  def create_table(self):
    self.table = QtWidgets.QTableWidget()
    self.table.setColumnCount(5)
    self.table.setColumnWidth(0, 5)
    self.table.setColumnWidth(1, 5)
    self.table.setColumnWidth(2, 1)
    self.table.setColumnWidth(3, 5)
    self.table.setColumnWidth(4, 5)
    self.table.setHorizontalHeaderLabels(["Dec", "Hex", "Char", "Count", "Percent"])
    self.table.verticalHeader().hide()
    self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

    printable = map(ord, string.printable[:-6])
    for byte, count in enumerate(self.counter):
      char = 0      
      if byte in printable:
        char = byte

      dec_item     = TableItem("%d" % byte,  TableItem.ItemType.DEC)
      hex_item     = TableItem("%x" % byte,  TableItem.ItemType.HEX)
      char_item    = TableItem("%c" % char,  TableItem.ItemType.TEXT)
      count_item   = TableItem("%d" % count, TableItem.ItemType.DEC)
      percert_item = TableItem("%s%%" % self.counts[byte], TableItem.ItemType.FLOAT)

      self.table.insertRow(byte)
      self.table.setItem(byte, 0, dec_item)
      self.table.setItem(byte, 1, hex_item)
      self.table.setItem(byte, 2, char_item)
      self.table.setItem(byte, 3, count_item)
      self.table.setItem(byte, 4, percert_item)

    self.table.horizontalHeader().setStretchLastSection(1);
    self.table.resizeRowsToContents()
    self.table.resizeColumnsToContents()
    self.table.setSortingEnabled(True)
    self.table.sortItems(3, QtCore.Qt.DescendingOrder)

class IDAtropyForm(PluginForm):
  def __init__(self):
    super(IDAtropyForm, self).__init__()
    self.config = Config()

    # disable timeout for scripts
    self.old_timeout = idaapi.set_script_timeout(0)

  def OnCreate(self, form):
    if USE_PYQT5:
      self.parent = self.FormToPyQtWidget(form)
    else:
      self.parent = self.FormToPySideWidget(form)
    self.PopulateForm()

  def RemoveTab(self, index):
    pass

  def PopulateForm(self):
    layout = QtWidgets.QVBoxLayout()

    self.tabs = QtWidgets.QTabWidget()
    self.tabs.setMovable(True)
    self.tabs.setTabsClosable(True)
    self.tabs.tabCloseRequested.connect(self.remove_tabs)
    self.tabs.addTab(Options(self), "Options")
    layout.addWidget(self.tabs)
    self.parent.setLayout(layout)

  def remove_tabs(self, index):
    if not isinstance(self.tabs.widget(index), Options):
      self.tabs.removeTab(index)

  def OnClose(self, form):
    idaapi.set_script_timeout(self.old_timeout)
    print "[%s] Form closed." % PLUG_NAME

class IDAtropy_t(plugin_t):
    flags = PLUGIN_UNL
    comment = "IDAtropy"
    help = ""
    wanted_name = PLUG_NAME
    wanted_hotkey = "Alt-F10"

    def init(self):
      self.icon_id = 0
      return PLUGIN_OK

    def run(self, arg=0):
      if not 'ERROR_MATPLOTLIB' in globals():
        f = IDAtropyForm()
        f.Show(PLUG_NAME)
      else:
        warning("%s - The plugin requires matplotlib" % PLUG_NAME)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return IDAtropy_t()

if __name__ == '__main__':
  log("Plugin loaded")
  #plg = IDAtropyForm().Show(PLUG_NAME)




