#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#  IDAtropy
#  last update: 2018/02/06
#
#  Daniel Garcia <danigargu [at] gmail.com>
#  @danigargu
# 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.
#

import sys
import math
import zlib
import string
import random

from idc import *
from idaapi import *
from idautils import *
from sets import Set

from collections import Counter, OrderedDict

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
  import sip
  import matplotlib
  import matplotlib.pyplot as plt
  import matplotlib.ticker as ticker
  from matplotlib.colors import hsv_to_rgb

  if USE_PYQT5:
    matplotlib.use('Qt5Agg')
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
  else:
    from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.backends.backend_qt4agg import NavigationToolbar2QT as NavigationToolbar
  from matplotlib.backend_bases import key_press_handler  
except ImportError:
  ERROR_MATPLOTLIB = True


PLUG_NAME    = "IDAtropy"
PLUG_VERSION = "v0.3"


def log(msg):
  Message("[%s] %s\n" % (PLUG_NAME, msg))

def histogram(data):
  table = [0]*256
  for i in map(ord, data):
    table[i] += 1
  return table

def gen_rand_colors(n_colors=20):
  """ https://martin.ankerl.com/2009/12/09/how-to-create-random-colors-programmatically/ """
  colors = []
  golden_ratio_conjugate = 0.618033988749895
  h = random.random()

  for i in range(n_colors):
    h += golden_ratio_conjugate
    h %= 1
    values = hsv_to_rgb([h, 0.3, 0.95])
    res = "#" + ''.join(["%02X" % int(val*256) for val in values])
    colors.append(res)

  return colors

def entropy_scan(data, block_size=256, step_size=1) :
  for block in (data[x:block_size+x] for x in xrange (0, len(data)-block_size, step_size)):
    yield entropy(block)

def entropy(data):
    """Calculate the entropy of a chunk of data."""

    if len(data) == 0:
        return 0.0

    occurences = Counter(bytearray(data))
    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x*math.log(p_x, 2)

    return entropy

def calc_compression_ratio(data):
  comp = zlib.compress(data)
  result = (float(len(comp))/len(data))*100
  if result > 100:
    result = 100
  return result

def get_loaded_bytes(start_addr, size, fill_with="\x00"):
  bytes = ""
  cur_ea = start_addr
  while cur_ea < (start_addr+size):
    if isLoaded(cur_ea):
      bytes += chr(get_byte(cur_ea))
    else:
      bytes += fill_with
    cur_ea += 1
  return bytes

def my_put_bytes(ea, buf):
  for i in xrange(len(buf)):
    patch_byte(ea+i, ord(buf[i]))

def get_disk_binary():
  data = None
  with open(get_input_file_path(), 'rb') as f:
    data = f.read()
  return data

def load_file_in_segment(filename, seg_name):
  last_seg = get_last_seg()
  seg_start = last_seg.endEA
  data = None

  with open(filename, 'rb') as f:
    data = f.read()

  seg_len = len(data)
  if seg_len % 0x1000 != 0:
    seg_len = seg_len + (0x1000 - (seg_len % 0x1000))

  if add_segm(0, seg_start, seg_start+seg_len, seg_name, "DATA"):
    put_bytes(seg_start, data)
    return True
  return False

class Config:
  chart_type   = 0
  start_addr   = 0
  end_addr     = 0
  use_disk_binary  = False
  use_debug_memory = False

  chart_types = ('Entropy','Histogram')

  xrefs = {
    "min_entropy": 6.8,
    "block_size": 256
  }

  entropy = {
    "all_segments": False,
    "block_size": 256,
    "step_size": 256,
    "segm_exists": False,
    "segm_addr": None,
    "segm_name": "IDAtropy"
  }

class ChartTypes:
  ENTROPY = 0
  HISTOGRAM = 1

class XrefsEntropy(Choose2):
  def __init__(self, title, config):
    Choose2.__init__(self, title, [ 
        ["Address", 16 | Choose2.CHCOL_HEX],
        ["Entropy", 10 | Choose2.CHCOL_DEC],
        ["Xrefs", 4 | Choose2.CHCOL_HEX],         
        ["Is code", 4 | Choose2.CHCOL_DEC],
        ["Xref Type", 15 | Choose2.CHCOL_PLAIN] ])

    self.title  = title
    self.items  = []
    self.icon   = 55 # xref icon
    self.config = config 
    self.PopulateItems()

  def OnClose(self):
    return True

  def OnSelectLine(self, n):
    item = self.items[int(n)]
    jumpto(int(item[0], 16))

  def OnGetLine(self, index):
    return self.items[index]

  def OnGetSize(self):
    return len(self.items)

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnGetLineAttr(self,n):
    pass

  def OnRefresh(self, n):
    return n

  def OnCommand(self, n, cmd_id):
    if cmd_id == self.cmd_exclude_code_xrefs:
      self.exclude_code_xrefs()  
    return n

  def exclude_code_xrefs(self):
    if not len(self.items):
      return False 

    self.items = [i for i in self.items if i[3] != '1']

    if IDA_SDK_VERSION >= 700:
      refresh_choosers()

    return True

  def show(self):
    n_items = len(self.items)
    if n_items > 0:
      b = self.Show()
      if b == 0:
        self.cmd_exclude_code_xrefs = self.AddCommand("Exclude code xrefs")
        return True
    else:
      warning("No xrefs found")
    return False

  def PopulateItems(self):
    min_entropy = self.config['min_entropy']
    cur_ea = self.config['start_addr']

    show_wait_box("Searching xrefs...")

    while cur_ea < self.config['end_addr']:
      xrefs = list(XrefsTo(cur_ea))
      if len(xrefs) > 0 and xrefs[0].type != fl_F: # discard ordinary flow
        bytes = get_bytes(cur_ea, self.config['block_size'])
        assert len(bytes) == self.config['block_size']

        ent = entropy(bytes)
        if ent >= min_entropy:
          self.items.append([
            "%08X" % cur_ea,
            "%.04f" % ent,
            "%d" % len(xrefs),
            "%d" % xrefs[0].iscode,
            "%s" % XrefTypeName(xrefs[0].type)              
          ])
      cur_ea += 1

    hide_wait_box()


class Options(QtWidgets.QWidget):
  def __init__(self, parent):
    QtWidgets.QWidget.__init__(self)
    self.parent = parent
    self.config = parent.config
    self.name = "Options"
    self.check_if_segm_exists()
    self.create_gui()

  def check_if_segm_exists(self):
    segm = get_segm_by_name(self.config.entropy['segm_name'])
    if segm:
      self.config.entropy['segm_exists'] = True
      self.config.entropy['segm_addr']   = segm.startEA
    else:
      self.config.entropy['segm_exists'] = False
      self.config.entropy['segm_addr']   = None

  def button_chart_on_click(self):
    try:      
      show_wait_box("Making chart...")
      tab_title = self.get_tab_title()

      if self.config.chart_type == ChartTypes.ENTROPY:
        if self.config.use_disk_binary and not self.config.entropy['segm_exists']:

          msg1 = "Do you want to create new segment with the binary content?\n"
          msg2 = "This will allow you to navigate over the file by double-clicking on the chart"
          if askyn_c(1, "HIDECANCEL\n" + msg1 + msg2) == 1:
            self.create_segment_with_binary()

        self.parent.tabs.addTab(Entropy(self), tab_title)

      elif self.config.chart_type == ChartTypes.HISTOGRAM:
        self.parent.tabs.addTab(Histogram(self), tab_title)
      
    except Exception, e:
      warning("%s" % traceback.format_exc())
    hide_wait_box()

  def button_xrefs_on_click(self):
    log("Start address : 0x%08x" % self.config.start_addr)
    log("End address : 0x%08x" % self.config.end_addr)

    xrefs_config = {
      "start_addr": self.config.start_addr,
      "end_addr": self.config.end_addr,
      "block_size": self.config.xrefs['block_size'],
      "min_entropy": float(self.t_min_entropy.text()),
    }    
    choose = XrefsEntropy("%s - XrefsTo" % PLUG_NAME, xrefs_config)
    choose.show()

  def create_segment_with_binary(self):
    segm_name = self.config.entropy['segm_name']
    if load_file_in_segment(GetInputFilePath(), segm_name):
      self.config.segm_exists = True
      self.check_if_segm_exists()

  def get_chart_type_str(self):
    return self.config.chart_types[self.config.chart_type]

  def get_tab_title(self):
    title = self.get_chart_type_str() + " - "
    if self.config.use_disk_binary:
      title += "Disk binary"
    elif self.config.entropy['all_segments']:
      title += "All segments"
    else:
      segname = SegName(self.config.start_addr)
      if segname:
        title += "%s " % segname
      title += "[0x%08x - 0x%08x]" % (self.config.start_addr, self.config.end_addr)
    return title

  def get_data(self):
    data = None
    if self.config.use_disk_binary:
      data = get_disk_binary()
    else:
      data_size = self.config.end_addr - self.config.start_addr
      data = get_bytes(self.config.start_addr, data_size)
    return data

  def update_progress_bars(self):
      data = self.get_data()
      ent = entropy(data)
      norm_ent = ent/8*100
      comp_ratio = calc_compression_ratio(data)

      self.pb_entropy.setValue(norm_ent)
      self.pb_entropy.setFormat("%0.2f" % ent)
      self.pb_comp_ratio.setValue(comp_ratio)

  def update_address(self):
    sender = self.sender()
    value = sender.text()

    if len(value) == 0 or value == "0x":
      return

    try:
      value = int(value, 16)
      if sender is self.t_start_addr:
        self.config.start_addr = value
      elif sender is self.t_end_addr:
        self.config.end_addr = value

      """ update progress bars """

      """
      if self.config.start_addr and self.config.end_addr \
        and self.config.start_addr < self.config.end_addr:

        self.update_progress_bars()
      """

    except ValueError as e:
      warning("Invalid value for address")

  def update_entropy_config(self):
    try:
      block_size = int(self.t_block_size.text())
      step_size = int(self.t_step_size.text())

      self.slider_block_s.setValue(block_size)
      self.slider_step_s.setValue(step_size)
      self.slider_step_s.setMaximum(block_size)

      self.config.entropy['block_size'] = block_size
      self.config.entropy['step_size'] = step_size
    except ValueError:
      log("Invalid value")
    
  def create_gui(self):
    lbl_start_address = QtWidgets.QLabel("Start address")
    self.t_start_addr = QtWidgets.QLineEdit()
    self.t_start_addr.setFixedWidth(200)

    lbl_end_address = QtWidgets.QLabel("End address")
    self.t_end_addr = QtWidgets.QLineEdit()
    self.t_end_addr.setFixedWidth(200)
    
    lbl_segment = QtWidgets.QLabel("Segment")
    self.cb_segment = QtWidgets.QComboBox()
    self.cb_segment.setFixedWidth(200)

    lbl_disk_binary = QtWidgets.QLabel("Use disk binary")
    self.cb_disk_bin = QtWidgets.QCheckBox()

    lbl_chart_type = QtWidgets.QLabel("Chart type")
    chart_types_group = self.create_chart_type_group()

    """ chunk size """
    ent_config = self.config.entropy

    lbl_block_size = QtWidgets.QLabel("Block size")
    lbl_block_size.setFixedWidth(60)
    self.t_block_size = QtWidgets.QLineEdit()
    self.t_block_size.setFixedWidth(40)
    self.t_block_size.setText("%d" % ent_config['block_size'])
    self.t_block_size.setToolTip("Size of the data blocks to calculate entropy")

    self.slider_block_s = QtWidgets.QSlider(QtCore.Qt.Horizontal)
    self.slider_block_s.setFixedWidth(70)
    self.slider_block_s.setMinimum(256)
    self.slider_block_s.setMaximum(4096)
    self.slider_block_s.setValue(ent_config['block_size'])
    self.slider_block_s.setSingleStep(8)

    hbox_block_s = QtWidgets.QHBoxLayout()
    hbox_block_s.addWidget(lbl_block_size)
    hbox_block_s.addWidget(self.t_block_size)
    hbox_block_s.addWidget(self.slider_block_s)
    
    """ step size """
    lbl_step_size = QtWidgets.QLabel("Step size")
    lbl_step_size.setFixedWidth(60)
    self.t_step_size = QtWidgets.QLineEdit()
    self.t_step_size.setFixedWidth(40)
    self.t_step_size.setText("%d" % ent_config['step_size'])

    msg1  = "Displacement in bytes between each iteration of entropy.\n"
    msg1 += "The step used must be less than or equal to the block size.\n\n"
    msg1 += "For example, 1 will get a list of entropies for all data offsets.\n"
    msg1 += "Step sizes greater will have less precision and will be normalized\n"
    msg1 += "in the mouse events on the chart."

    self.t_step_size.setToolTip(msg1)

    self.slider_step_s = QtWidgets.QSlider(QtCore.Qt.Horizontal)
    self.slider_step_s.setFixedWidth(70)
    self.slider_step_s.setMinimum(1)
    self.slider_step_s.setMaximum(ent_config['block_size'])
    self.slider_step_s.setValue(ent_config['step_size'])

    hbox_step = QtWidgets.QHBoxLayout()
    hbox_step.addWidget(lbl_step_size)
    hbox_step.addWidget(self.t_step_size)
    hbox_step.addWidget(self.slider_step_s)

    """ All segments """
    lbl_all_segments = QtWidgets.QLabel("All segments")
    self.cb_all_segments = QtWidgets.QCheckBox()

    """ entropy config """
    form_entropy =  QtWidgets.QFormLayout()
    form_entropy.addRow(lbl_all_segments, self.cb_all_segments)
    form_entropy.addRow(hbox_block_s)
    form_entropy.addRow(hbox_step)
    self.groupbox_entropy = QtWidgets.QGroupBox('Entropy chart config')
    self.groupbox_entropy.setLayout(form_entropy)
    self.groupbox_entropy.setFixedWidth(300)

    lbl_min_entropy = QtWidgets.QLabel("Min entropy")
    lbl_block_s_xref = QtWidgets.QLabel("Block size")
    self.t_min_entropy = QtWidgets.QLineEdit()
    self.t_block_s_xrefs = QtWidgets.QLineEdit()
    self.t_min_entropy.setFixedWidth(80)
    self.t_block_s_xrefs.setFixedWidth(80)
    self.t_min_entropy.setText("%.02f" % self.config.xrefs['min_entropy'])
    self.t_block_s_xrefs.setText("%d" % self.config.xrefs['block_size'])

    form_xrefs = QtWidgets.QFormLayout()
    form_xrefs.addRow(lbl_min_entropy, self.t_min_entropy)
    form_xrefs.addRow(lbl_block_s_xref, self.t_block_s_xrefs)

    groupbox_xrefs = QtWidgets.QGroupBox('Xrefs finder')
    groupbox_xrefs.setLayout(form_xrefs)
    groupbox_xrefs.setFixedWidth(300)

    """ progress bars """
    progress_bar_style = """
    QProgressBar {
        border: 1px solid grey;
        border-radius: 2px;
        text-align: center;
    }

    QProgressBar::chunk {
        background-color: #BDE99F;
        width: 4px;
    }"""

    lbl_compress_ratio = QtWidgets.QLabel("Compression ratio") 
    self.pb_comp_ratio = QtWidgets.QProgressBar()
    self.pb_comp_ratio.setStyleSheet(progress_bar_style)
    self.pb_comp_ratio.setFixedWidth(200)

    lbl_entropy = QtWidgets.QLabel("Shannon entropy") 
    self.pb_entropy = QtWidgets.QProgressBar()
    self.pb_entropy.setStyleSheet(progress_bar_style)
    self.pb_entropy.setFixedWidth(200)

    """ buttons """
    self.button_chart = QtWidgets.QPushButton("Draw chart")
    self.button_chart.setFixedWidth(100)

    self.button_xrefs = QtWidgets.QPushButton("Find Xrefs")
    self.button_xrefs.setFixedWidth(100)

    hbox_buttons = QtWidgets.QHBoxLayout()
    hbox_buttons.addWidget(self.button_chart)
    hbox_buttons.addWidget(self.button_xrefs)

    """ main form """
    main_form = QtWidgets.QFormLayout()
    main_form.addRow(lbl_start_address, self.t_start_addr)
    main_form.addRow(lbl_end_address, self.t_end_addr)
    main_form.addRow(lbl_segment, self.cb_segment)
    main_form.addRow(lbl_compress_ratio, self.pb_comp_ratio)
    main_form.addRow(lbl_entropy, self.pb_entropy)
    main_form.addRow(lbl_disk_binary, self.cb_disk_bin)
    main_form.addRow(lbl_chart_type, chart_types_group)
    main_form.addRow(self.groupbox_entropy)
    main_form.addRow(groupbox_xrefs)  
    main_form.addRow(hbox_buttons)
    main_form.setAlignment(QtCore.Qt.AlignLeft)

    """ signals """
    self.cb_segment.currentIndexChanged[int].connect(self.cb_segment_changed)
    self.cb_all_segments.stateChanged.connect(self.cb_changed)
    self.cb_disk_bin.stateChanged.connect(self.cb_changed)
    self.button_chart.clicked.connect(self.button_chart_on_click)
    self.button_xrefs.clicked.connect(self.button_xrefs_on_click)

    for widget in [self.slider_block_s, self.slider_step_s]:
      widget.valueChanged.connect(self.slider_valuechanged)

    for widget in [self.t_start_addr, self.t_end_addr]:
      widget.textChanged.connect(self.update_address)

    for widget in [self.t_block_size, self.t_step_size]:
      widget.textChanged.connect(self.update_entropy_config)

    self.fill_segments()
    self.setLayout(main_form)

  def slider_valuechanged(self):
    sender = self.sender()
    value = int(sender.value())

    if sender is self.slider_step_s:
      self.t_step_size.setText("%d" % value)
      self.config.entropy['step_size']  = value

    elif sender is self.slider_block_s:      
      self.t_block_size.setText("%d" % value)
      self.config.entropy['block_size'] = value

  def cb_changed(self, state):
    sender = self.sender()

    if sender is self.cb_disk_bin:
      checked = (state == QtCore.Qt.Checked)  
      self.config.use_disk_binary = checked
      b_enabled = not checked

      self.update_progress_bars()

      self.t_start_addr.setEnabled(b_enabled)
      self.t_end_addr.setEnabled(b_enabled)
      self.cb_segment.setEnabled(b_enabled)
      self.cb_all_segments.setEnabled(b_enabled)

    elif sender is self.cb_all_segments:
      checked = (state == QtCore.Qt.Checked)
      self.config.entropy['all_segments'] = checked
      self.cb_disk_bin.setEnabled(not checked)

  def fill_segments(self):
    segments = filter(self.segment_filter, Segments())

    for idx, s_ea in enumerate(segments):
      if idx == 0:
        self.set_address(SegStart(s_ea), SegEnd(s_ea))
      self.cb_segment.addItem(SegName(s_ea), s_ea)

    if not segments:
      self.set_address(MinEA(), MaxEA())
      self.cb_segment.setEnabled(False)

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
    selected_id = self.rg_chart_type.checkedId()
    self.config.chart_type = selected_id

    b_enabled = (self.get_chart_type_str() == 'Entropy')
    self.groupbox_entropy.setEnabled(b_enabled)

  def cb_segment_changed(self, value):
    s_ea = self.sender().itemData(value)
    self.set_address(SegStart(s_ea), SegEnd(s_ea))
    self.update_progress_bars()   

  def set_address(self, start_addr, end_addr):
    self.t_start_addr.setText("0x%x" % start_addr)
    self.t_end_addr.setText("0x%x" % end_addr)

  def segment_filter(self, s_ea):
    """ Discard extern segments """
    if GetSegmentAttr(s_ea, SEGATTR_TYPE) != SEG_XTRN and \
     SegName(s_ea) != self.config.entropy['segm_name']:
      return True
    return False


class Entropy(QtWidgets.QWidget):
  def __init__(self, parent):
    QtWidgets.QWidget.__init__(self)
    self.parent         = parent
    self.config         = parent.config
    self.entropy_cfg    = self.config.entropy
    self.segments       = None
    self.data           = None
    self.data_size      = None
    self.calc_addr_fcn  = None
    self.make_chart()

  def make_chart(self):
    if self.entropy_cfg['all_segments']:
      self.get_segments_memory()
      self.make_segments_chart()
    else:
      self.get_data()
      self.make_normal_chart()

  def segment_filter(self, s_ea):
    """ Discard extern segments """
    if GetSegmentAttr(s_ea, SEGATTR_TYPE) != SEG_XTRN and \
     SegName(s_ea) != self.config.entropy['segm_name']:
      return True
    return False

  def get_data(self):
    data = None
    if self.config.use_disk_binary:
      data = get_disk_binary()
    else:
      data_size = self.config.end_addr - self.config.start_addr
      data = get_bytes(self.config.start_addr, data_size)

    self.data = data
    self.data_size = len(data)

  def format_coord_segments(self, x, y):
    try:
      addr = self.calc_addr_fcn(int(x))
      return "0x%08X - %-20s" % (addr, SegName(addr))
    except:
      return 'bad address'

  def get_segments_memory(self):    
    memory = ""
    step_size = self.entropy_cfg['step_size']
    segments  = OrderedDict()

    for ea in filter(self.segment_filter, Segments()):
      seg_name = SegName(ea)
      segm  = get_segm_by_name(seg_name)
      bytes = get_bytes(segm.startEA, segm.size())
      assert len(bytes) == segm.size()

      start_offset = len(memory)
      end_offset   = (start_offset+len(bytes))

      seg_info = {
        'segm': segm,
        'entropy': entropy(bytes),
        'offsets': [
          start_offset ,
          end_offset
        ],
        'chart_offsets': [
          start_offset / step_size, 
          end_offset / step_size
        ]
      }
      segments[seg_name] = seg_info
      memory += bytes

    self.data = memory
    self.data_size = len(memory)
    self.segments = segments

  def calc_point_addr_segments(self, x):
    addr = None
    for segm_name, segm_info in self.segments.iteritems():
      start, end = segm_info['chart_offsets']
      if start <= x < end:
        norm_x = (x-start) * self.entropy_cfg['step_size']
        addr = segm_info['segm'].startEA + norm_x
        break
    return addr

  def calc_point_addr_normal(self, x):
    addr = None
    offset = x * self.config.entropy['step_size']
    if self.config.use_disk_binary and self.config.entropy['segm_exists']:
      addr = self.config.entropy['segm_addr'] + offset
    else:
      addr = self.config.start_addr + offset
    return addr

  def segment_changed(self, item):
      row = item.row()
      col = item.column()
      seg_name = item.text()

      if (item.checkState() == QtCore.Qt.Checked):
        start, end = self.segments[seg_name]['chart_offsets']
        aspan = plt.axvspan(start, end, color=self.colors[row % len(self.colors)], alpha=0.6)
        self.spans[seg_name] = aspan      
      else:
        if seg_name in self.spans.keys():
          self.spans[seg_name].remove()
          del self.spans[seg_name]      
      self.canvas.draw()

  def make_segments_chart(self):    
    segment_names = []
    x_axis = []

    self.calc_addr_fcn = self.calc_point_addr_segments

    for segm_name, seg_info in self.segments.iteritems():
      segment_names.append(segm_name)
      x_axis.append(seg_info['chart_offsets'][0])

    x_limit = self.data_size / self.entropy_cfg['step_size']
    self.colors = gen_rand_colors(25)

    self.spans = dict()
    results = list(entropy_scan(self.data, 
      self.config.entropy['block_size'], 
      self.config.entropy['step_size'])
    )

    blocks = len(results)
    min_value, max_value  = min(results), max(results)
    avg_values = sum(results) / len(results)

    #plt.rc('xtick', labelsize=6)
    #plt.rc('ytick', labelsize=6)

    self.fig = plt.figure(facecolor='white')
    ax = plt.subplot(111, facecolor='white')

    ax.set_xlabel("byte range / blocks")
    ax.set_ylabel("Entropy (E)")

    ax2 = ax.twiny()
    ax2.set_xlabel("Segments")
    ax2.set_xlim(0, x_limit)
    ax2.set_xticks(x_axis)

    labels = ax2.set_xticklabels(segment_names, rotation=40)
    ax.axis([0, blocks, 0, 8])

    ax2.format_coord = self.format_coord_segments
    plt.plot(results, color="#2E9AFE")
    plt.tight_layout()
   
    log("Entropy - Start address: 0x%08x" % self.config.start_addr)
    log("Entropy - End address:   0x%08x" % self.config.end_addr)
    log("Entropy - Data size: %d bytes (blocks: %d)" % (len(self.data), blocks))
    info_str = 'Entropy - Min: %.2f | Max:  %.2f | Avg: %.2f' % (min_value, max_value, avg_values)
    log(info_str)

    del self.data

    self.canvas  = FigureCanvas(self.fig)
    self.toolbar = NavigationToolbar(self.canvas, self)

    self.cb_jump_on_click = QtWidgets.QCheckBox("Disable double-click event")    
    self.cb_jump_on_click.stateChanged.connect(self.disable_jump_on_click)

    """ segment table """
    self.segments_table = QtWidgets.QTableView()
    self.segments_table.setMaximumWidth(200)
    self.segments_table.setMaximumHeight(200)
    self.segments_table.verticalHeader().hide()

    model = QtGui.QStandardItemModel()
    model.setHorizontalHeaderLabels(['Segment','Entropy'])
    model.setHeaderData(0, QtCore.Qt.Horizontal, QtCore.Qt.AlignJustify, QtCore.Qt.TextAlignmentRole)
    
    self.segments_table.setSelectionMode(QtWidgets.QTableView.SingleSelection)
    self.segments_table.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
    self.segments_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    self.segments_table.setModel(model)

    for n, seg_name in enumerate(segment_names):
      segment_name = QtGui.QStandardItem(seg_name)
      segment_entropy = QtGui.QStandardItem("%.03f" % self.segments[seg_name]['entropy'])
      model.setItem(n, 0, segment_name)
      model.setItem(n, 1, segment_entropy)
      segment_name.setCheckable(True)

    self.segments_table.horizontalHeader().setStretchLastSection(1);
    self.segments_table.resizeRowsToContents()
    self.segments_table.resizeColumnsToContents()
    self.segments_table.sortByColumn(1, QtCore.Qt.DescendingOrder)
    model.itemChanged.connect(self.segment_changed)
    
    lbl_segments = QtWidgets.QLabel("Select a segment to color it")
    vbox = QtWidgets.QVBoxLayout(self)
    vbox.addWidget(lbl_segments)
    vbox.addWidget(self.segments_table)

    group = QtWidgets.QGroupBox()
    group.setFlat(True)
    group.setStyleSheet("border:0")
    group.setLayout(vbox)    

    grid = QtWidgets.QGridLayout()
    grid.addWidget(self.canvas, 0, 0, 1, 2)
    grid.addWidget(group, 0, 3, QtCore.Qt.AlignCenter)
    grid.addWidget(self.toolbar, 1, 0)
    grid.addWidget(self.cb_jump_on_click, 2, 0)

    self.cid = self.fig.canvas.mpl_connect('button_press_event', self.on_click)

    self.setLayout(grid)
    
  def on_click(self, event):
    if event.dblclick and event.xdata:
      addr = self.calc_addr_fcn(int(event.xdata))
      if addr:
        jumpto(addr)
      else:
        warning("Unable to calculate the address")

  def format_coord_normal(self, x, y):
    try:
      if self.config.use_disk_binary or self.entropy_cfg['segm_exists']:
        addr = int(x) * self.config.entropy['step_size']
        return "Offset : 0x%08x %-30s" % (addr, "")
      else:
        addr = self.calc_addr_fcn(int(x))
        return "0x%08x - %-30s" % (addr, SegName(addr))       
    except:
      pass
    return "bad address"

  def make_normal_chart(self):
    blocks = self.data_size / self.entropy_cfg['block_size']
    self.calc_addr_fcn = self.calc_point_addr_normal

    results = list(entropy_scan(self.data, 
      self.entropy_cfg['block_size'], 
      self.entropy_cfg['step_size'])
    )
    min_value, max_value  = min(results), max(results)
    avg_values = sum(results) / len(results)

    self.fig = plt.figure(facecolor='white')
    ax = plt.subplot(111, facecolor='white')
    ax.axis([0, len(results), 0, 8])
    ax.format_coord = self.format_coord_normal
    plt.plot(results, color="#2E9AFE")    

    log("Entropy - Start address: 0x%08x" % self.config.start_addr)
    log("Entropy - End address:   0x%08x" % self.config.end_addr)
    log("Entropy - Data size: %d bytes (blocks: %d)" % (self.data_size, blocks))
    info_str = 'Entropy - Min: %.2f | Max:  %.2f | Avg: %.2f' % (min_value, max_value, avg_values)
    log(info_str)
    del self.data

    plt.xlabel('Byte range')
    plt.ylabel('Entropy')
    plt.title('Entropy levels')

    self.canvas = FigureCanvas(self.fig)
    self.toolbar = NavigationToolbar(self.canvas, self)
    self.line_edit = QtWidgets.QLineEdit()

    self.cb_jump_on_click = QtWidgets.QCheckBox("Disable double-click event")    
    self.cb_jump_on_click.stateChanged.connect(self.disable_jump_on_click)

    grid = QtWidgets.QGridLayout()
    grid.addWidget(self.canvas, 0, 0)
    grid.addWidget(self.toolbar, 1, 0)

    if not self.config.use_disk_binary or self.entropy_cfg['segm_exists']:
      grid.addWidget(self.cb_jump_on_click, 2, 0)
      self.cid = self.fig.canvas.mpl_connect('button_press_event', self.on_click)

    self.setLayout(grid)

  def disable_jump_on_click(self, state):
    if state == QtCore.Qt.Checked:
      self.fig.canvas.mpl_disconnect(self.cid)
    else:
      self.cid = self.fig.canvas.mpl_connect('button_press_event', self.on_click)


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
  def __init__(self, parent):
    QtWidgets.QWidget.__init__(self)
    self.parent   = parent
    self.config   = parent.config
    self.data     = None
    self.data_size = None
    self.get_data()
    self.make_histogram()

  def get_data(self):
    data = None

    if self.config.use_disk_binary:
      data = get_disk_binary()
    else:
      data_size = self.config.end_addr - self.config.start_addr
      data = get_loaded_bytes(self.config.start_addr, data_size, "")

    self.data = data
    self.data_size = len(data)

  def format_coord(self, x, y):    
    try:
      value = int(x)
      return "value: %d | count: %-30s" % (value, self.counter[value] )
    except:
      pass
    return "bad value"

  def make_histogram(self):    
    self.counter   = histogram(self.data)
    self.counts    = [round(100*float(byte_count)/self.data_size, 2) for byte_count in self.counter] 
    top_y          = math.ceil(max(self.counts)*10.0)/10.0
    del self.data

    self.create_table()
    fig = plt.figure(facecolor='white')
    ax = plt.subplot(111, facecolor='white')

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
    ax.set_xlim(0, 255)
    ax.set_xticks([0, 64, 128, 192, 255])
    ax.format_coord = self.format_coord

    bar_colors = ['#2040D0','#2E9AFE']
    ax.bar(range(256), self.counts, width=1, edgecolor="black", linewidth=0.4, color=bar_colors*128)

    plt.title("Byte histogram")
    plt.xlabel('Byte range')
    plt.ylabel('Occurance [%]')

    self.canvas  = FigureCanvas(fig)
    self.toolbar = NavigationToolbar(self.canvas, self)

    grid = QtWidgets.QGridLayout()
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
      hex_item     = TableItem("%02X" % byte,TableItem.ItemType.HEX)
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
    self.table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)  

def make_ida6_compatible():
  """ Compatibility between IDA 6.X and 7.X """

  global get_bytes
  global put_bytes

  if IDA_SDK_VERSION < 700:
    get_bytes = get_loaded_bytes
    put_bytes = my_put_bytes

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
    self.tabs = QtWidgets.QTabWidget()
    self.tabs.setMovable(True)
    self.tabs.setTabsClosable(True)
    self.tabs.tabCloseRequested.connect(self.remove_tabs)
    self.tabs.addTab(Options(self), "Options")

    layout = QtWidgets.QVBoxLayout()
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
      make_ida6_compatible()
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
  


