# -*- coding: UTF-8 -*-
from __future__ import print_function
import numpy as np
import pandas as pd
import os
from scipy.stats import pearsonr
import datetime
import threading
from functools import cmp_to_key
import math
import sys
from scipy.optimize import dual_annealing
import pickle
import csv

class RT_Detection:
    """This class is designed for RT type anomaly detection

    Attributes:
        current: detection window before the alarm
        comparison_today: today's comparison window
        comparison_day_before: yesterday's comparison window
        comparison_7days_before: comparison window 7 days before

    """
    def __init__(self, current, comparison_today, comparison_day_before, comparison_7days_before):
        self.current = current
        self.comparison_today = comparison_today
        self.comparison_day_before = comparison_day_before
        self.comparison_7days_before = comparison_7days_before
    
    def detection(self):

        self.number_of_over_max_values0 = 0
        self.delta_of_maximum_values0 = 0
        self.number_of_over_average_values0 = 0
        self.ratio_of_average_values0 = 0

        self.number_of_over_max_values1 = 0
        self.delta_of_maximum_values1 = 0
        self.number_of_over_average_values1 = 0
        self.ratio_of_average_values1 = 0

        self.number_of_over_max_values7 = 0
        self.delta_of_maximum_values7 = 0
        self.number_of_over_average_values7 = 0
        self.ratio_of_average_values7 = 0

        maximum_value_in_comparison_window0 = -1
        maximum_value_in_comparison_window1 = -1
        maximum_value_in_comparison_window7 = -1
        valid_count = 0
        comparison_sum = 0

        for point in self.comparison_today:
            if (not np.isnan(point)):
                maximum_value_in_comparison_window0 = max(maximum_value_in_comparison_window0, point)
                valid_count = valid_count+1
                comparison_sum = comparison_sum+point
        if valid_count != 0:
            average_value_in_comparison_window0 = comparison_sum/valid_count
        else:
            average_value_in_comparison_window0 = 0
        comparison_sum = 0
        valid_count = 0

        for point in self.comparison_day_before:
            if not np.isnan(point):
                maximum_value_in_comparison_window1 = max(maximum_value_in_comparison_window1, point)
                valid_count = valid_count+1
                comparison_sum = comparison_sum+point
        if valid_count != 0:
            average_value_in_comparison_window1 = comparison_sum/valid_count
        else:
            average_value_in_comparison_window1 = 0
        comparison_sum = 0
        valid_count = 0

        for point in self.comparison_7days_before:
            if not np.isnan(point):
                maximum_value_in_comparison_window7 = max(maximum_value_in_comparison_window7, point)
                valid_count = valid_count+1
                comparison_sum = comparison_sum+point
        if valid_count != 0:
            average_value_in_comparison_window7 = comparison_sum/valid_count
        else:
            average_value_in_comparison_window7 = 0
        valid_count = 0
        detection_sum = 0

        for point in self.current:
            if not np.isnan(point):
                valid_count = valid_count+1
                detection_sum = detection_sum+point
        if valid_count != 0:
            average_value_in_detection_window = detection_sum/valid_count
        else:
            average_value_in_detection_window = 0

        maximum_value_in_detection_window = -1
        for point in self.current:
            if (not np.isnan(point)) and point > maximum_value_in_comparison_window0:
                self.number_of_over_max_values0 = self.number_of_over_max_values0+1
            if (not np.isnan(point)) and point > maximum_value_in_comparison_window1:
                self.number_of_over_max_values1 = self.number_of_over_max_values1+1
            if (not np.isnan(point)) and point > maximum_value_in_comparison_window7:
                self.number_of_over_max_values7 = self.number_of_over_max_values7+1

            if not np.isnan(point):
                maximum_value_in_detection_window = max(maximum_value_in_detection_window, point)
            
            if (not np.isnan(point)) and point > average_value_in_comparison_window0:
                self.number_of_over_average_values0 = self.number_of_over_average_values0 + 1
            if (not np.isnan(point)) and point > average_value_in_comparison_window1:
                self.number_of_over_average_values1 = self.number_of_over_average_values1 + 1
            if (not np.isnan(point)) and point > average_value_in_comparison_window7:
                self.number_of_over_average_values7 = self.number_of_over_average_values7 + 1

        self.delta_of_maximum_values0 = maximum_value_in_detection_window - maximum_value_in_comparison_window0
        self.delta_of_maximum_values1 = maximum_value_in_detection_window - maximum_value_in_comparison_window1
        self.delta_of_maximum_values7 = maximum_value_in_detection_window - maximum_value_in_comparison_window7
        
        if average_value_in_comparison_window0 != 0:
            self.ratio_of_average_values0 = average_value_in_detection_window/average_value_in_comparison_window0
        else:
            self.ratio_of_average_values0 = 0

        if average_value_in_comparison_window1 != 0:
            self.ratio_of_average_values1 = average_value_in_detection_window/average_value_in_comparison_window1
        else:
            self.ratio_of_average_values1 = 0

        if average_value_in_comparison_window7 != 0:
            self.ratio_of_average_values7 = average_value_in_detection_window/average_value_in_comparison_window7
        else:
            self.ratio_of_average_values7 = 0
        
        return [self.number_of_over_max_values0, self.delta_of_maximum_values0, self.number_of_over_average_values0, self.ratio_of_average_values0, 
                self.number_of_over_max_values1, self.delta_of_maximum_values1, self.number_of_over_average_values1, self.ratio_of_average_values1,
                self.number_of_over_max_values7, self.delta_of_maximum_values7, self.number_of_over_average_values7, self.ratio_of_average_values7]

class Span:
    """This class represents 'call' in our framework

    Attributes:
        caller: the caller node of this call
        callee: the callee node of this call
        metric: time series data of this call
        entry_span: the entry call related to this call whose caller or callee violates the SLO requirements
        is_entry: a boolean variable that indicates whether this call is an entry
    
    """
    def __init__(self, caller, callee, metric, entry_span=None, is_entry=False):
        self.caller = caller
        self.callee = callee
        self.metric = metric
        self.entry_span = entry_span

        self.callgraph_index = -1

        self.qpm_anomaly = False
        self.ec_anomaly = False
        self.rt_anomaly = False

        self.ec_beta = 0.0
        self.rt_beta = 0.0

        self.is_entry = is_entry

        if str(type(self.caller)) == "<class '__main__.Node'>":
            if self.caller.server == item_server or self.callee.server == item_server:
                self.is_entry = True
        else:
            if self.caller[0] == item_server or self.callee[0] == item_server:
                self.is_entry=True
        
        self.extra_span = False

    def __eq__(self, span):
        if span == None:
            return False
        return self.caller == span.caller and self.callee == span.callee

    def __hash__(self):
        return hash(self.caller)+hash(self.callee)

    def __str__(self):
        return str(self.caller)+' \n'+str(self.callee)

    def get_caller(self):
        return self.caller

    def get_callee(self):
        return self.callee

    def normalize_metric(self):
        span_str = str(self.get_caller())+' '+str(self.get_callee())
        try:
            request_list = split_data(self.metric[0])
        except:
            request_list = [np.nan]*1440
        
        try:
            duration_list = split_data(self.metric[1])
        except:
            duration_list = [np.nan]*1440

        try:
            exception_list = split_data(self.metric[2])
        except:
            exception_list = [np.nan]*1440
        
        try:
            timeout_list = split_data(self.metric[3])
        except:
            timeout_list = [np.nan]*1440

        self.qpm = request_list
        self.ec = [np.nan]*1440
        self.rt = [np.nan]*1440

        for exception, timeout, index in zip(exception_list, timeout_list, range(0,1440)):
            if (not np.isnan(exception)) and (not np.isnan(timeout)):
                self.ec[index] = exception + timeout
        
        for duration, request, index in zip(duration_list, request_list, range(0, 1440)):
            if (not np.isnan(duration)) and (not np.isnan(duration)):
                self.rt[index] = duration/request

    def compute_pearsonr_to_entry_span(self):

        if self.is_entry == True:
            self.entry_span = self

        compare_ec = self.entry_span.ec
        compare_rt = self.entry_span.rt

        data1_ec = []
        data2_ec = []

        data1_rt = []
        data2_rt = []

        for data_point, compare_point in zip(self.ec, compare_ec):
            if (not np.isnan(data_point)) and (not np.isnan(compare_point)):
                data1_ec.append(data_point)
                data2_ec.append(compare_point)

        for data_point, compare_point in zip(self.rt, compare_rt):
            if (not np.isnan(data_point)) and (not np.isnan(compare_point)):
                data1_rt.append(data_point)
                data2_rt.append(compare_point)

        try:
            if len(data1_ec) > 10:
                ec_similarity, _ = pearsonr(data1_ec, data2_ec)
                self.ec_similarity = abs(ec_similarity)
            else:
                self.ec_similarity = 0.0

            if len(data1_rt) > 10:
                rt_similarity, _ = pearsonr(data1_rt, data2_rt)
                self.rt_similarity = abs(rt_similarity)
            else:
                self.rt_similarity = 0.0
        except:
            pass

    def metric_valid(self):
        qpm_count = 0
        ec_count = 0
        rt_count = 0

        for i, j, k in zip(self.qpm, self.ec, self.rt):
            if not np.isnan(i):
                qpm_count = qpm_count + 1
            if not np.isnan(j):
                ec_count = ec_count + 1
            if not np.isnan(k):
                rt_count = rt_count + 1
        
        return qpm_count > 20 and ec_count > 20 and rt_count > 20

    def metric_valid_30_mins_before_alarm(self, alarm_time):
        if alarm_time > 30:
            qpm_count = 0
            ec_count = 0
            rt_count = 0

            for i, j, k in zip(self.qpm[alarm_time-30:alarm_time], self.ec[alarm_time-30:alarm_time], self.rt[alarm_time-30:alarm_time]):
                if not np.isnan(i):
                    qpm_count = qpm_count + 1
                if not np.isnan(j):
                    ec_count = ec_count + 1
                if not np.isnan(k):
                    rt_count = rt_count + 1
            return qpm_count>=5 and ec_count>=5 and rt_count>=5
        else:
            return False

class Node:
    """This class represents one end of a call(caller or callee)
    
        Attributes:
            server: name of the service
            service: name of the port
            method: method name
            set: custom tag

    """

    def __init__(self, server, service, method, set):
        self.server = server
        self.service = service
        self.method = method
        self.set = set

        self.depth = 0
        self.list_index = -1
        self.callgraph_index = -1

    def __eq__(self, node):
        if node == None:
            return False
        return self.server == node.server and self.service == node.service and self.method == node.method and self.set == node.set

    def __hash__(self):
        return hash(self.server+self.service+self.method+self.set)

    def __str__(self):
        return '('+self.server+','+self.service+','+self.method+','+self.set+')'

    def __add__(self, node):
        return self.get_turple() + node.get_turple()

    def get_turple(self):
        return (self.server, self.service, self.method, self.set)

class Root_Cause:
    """This class represents the root cause founded during the exploration stage

    """
    def __init__(self, span, turple, root_score):
        self.turple = turple
        self.root_score = root_score
        self.span = span

        ec_sum = 0
        request_sum = 0
        for point in self.span.qpm[alarm_time-10:alarm_time]:
            if (not np.isnan(point)):
                request_sum = request_sum + point
        for point in self.span.ec[alarm_time-10:alarm_time]:
            if (not np.isnan(point)):
                ec_sum  = ec_sum + point
        if request_sum != 0:
            self.error_rate = ec_sum / request_sum
        else:
            self.error_rate = 0

    def __eq__(self, root_cause):
        if root_cause == None:
            return False
        else:
            return self.turple == root_cause.turple

class Root_Cause_Server:
    """This class represents the root cause aggregate to the server scale
    
    """

    def __init__(self, server, root_cause_lsit):
        self.server = server
        self.root_cause_list = root_cause_lsit
        self.root_cause_number = len(root_cause_lsit)
        self.max_root_score = 0.0
        self.max_error_rate = 0.0
        sum_error_rate = 0.0

        sum = 0.0
        for root_cause in self.root_cause_list:
            sum = sum + root_cause.root_score
            self.max_root_score = max(self.max_root_score, root_cause.root_score)
            self.max_error_rate = max(self.max_error_rate, root_cause.error_rate)
            sum_error_rate = sum_error_rate + root_cause.error_rate

        self.average_root_score = sum / self.root_cause_number
        self.average_error_rate = sum_error_rate/self.root_cause_number

    def __eq__(self, target):
        if target == None:
            return False
        else:
            return self.server == target.server and self.root_cause_list == target.root_cause_list

    def __str__(self):
        self_str = self.server + '\n'
        return self_str

class Regression_Pruning:
    """This class works during thr regression pruning stage
    
    """

    def __init__(self, downstream_span, compare_span_list):
        self.downstream_span = downstream_span
        self.compare_span_list = compare_span_list
        self.lack_data=False
        self.compute_regression()

    def compute_regression(self):
        temp_turple = (self.downstream_span, )
        for span in self.compare_span_list:
            temp_turple = temp_turple + (span, )

        global similarity_array_dict

        if str(type(similarity_array_dict.get(temp_turple))) != "<class 'NoneType'>":
            similarity_result = similarity_array_dict[temp_turple]
            self.real_upstream_span_list = []
            for index, similarity in enumerate(similarity_result):
                if similarity > regression_threshold:
                    self.real_upstream_span_list.append(self.compare_span_list[index])

        else:
            array_u = list()
            array_d = list()
            for span in self.compare_span_list:
                array_u.append(list())
            
            for index in range(0, 1440):
                flag = True
                for span in self.compare_span_list:
                    if np.isnan(span.qpm[index]):
                        flag = False
                if np.isnan(self.downstream_span.qpm[index]):
                    flag = False
                
                if flag:
                    for index_2, span in enumerate(self.compare_span_list):
                        array_u[index_2].append(span.qpm[index])
                    array_d.append(self.downstream_span.qpm[index])
            flag = False
            if len(array_d) == 0:
                flag = True
            array_d = np.array(array_d)
            array_us = np.array(array_u)
            X = np.transpose(array_us)


            if not flag:
                similarity_result = linear_model_func(X, array_d)
                similarity_array_dict[temp_turple] = similarity_result
                self.real_upstream_span_list = []

                for index, similarity in enumerate(similarity_result):
                    if similarity > regression_threshold:
                        self.real_upstream_span_list.append(self.compare_span_list[index])
            else:
                self.real_upstream_span_list = self.compare_span_list

def linear_model_func(A1,b1):
    num_x = np.shape(A1)[1]
    global regression_param
    theta = []
    for i in range(0, num_x):
        theta.append(1/num_x)

    def my_func(x):
        ls = (b1-np.dot(A1,x))**2
        result = np.sum(ls)
        return result
    bnds = [(0,regression_param)]
    for i in range(num_x-1):
        bnds.append((0,regression_param))

    res1 = dual_annealing(my_func, bounds = bnds, maxiter=1000)
    return res1.x

class Callgraph:
    """This class represents the call graph in our framework
    
    """

    def __init__(self, all_spans, entry_spans):
        self.all_spans = all_spans
        self.entry_spans = entry_spans
        self.all_nodes = []
        self.ec_anomaly_entry_spans = []
        self.rt_anomaly_entry_spans = []
        self.adjancy_matrix = []
        self.generate_all_nodes()
        self.normalize_all_spans()
        self.generate_adjacency_matrix()

    def normalize_all_spans(self):
        for span in self.all_spans:
            span.normalize_metric()
            if span.caller.server == item_server or span.callee.server == item_server:
                span.is_entry = True
            anomaly_detection_for_one_span(span)
            if span.is_entry and span.ec_anomaly:
                self.ec_anomaly_entry_spans.append(span)
            if span.is_entry and span.rt_anomaly:
                self.rt_anomaly_entry_spans.append(span)

    def generate_all_nodes(self):
        for span in self.all_spans:
            if str(type(span.get_caller())) == "<class '__main__.Node'>":
                caller_node = Node(*span.get_caller().get_turple())
                callee_node = Node(*span.get_callee().get_turple())
            else:
                caller_node = Node(*span.get_caller())
                callee_node = Node(*span.get_callee())

            if caller_node not in self.all_nodes:
                self.all_nodes.append(caller_node)
                span.caller = caller_node
            else:
                span.caller = self.all_nodes[self.all_nodes.index(caller_node)]
            if callee_node not in self.all_nodes:
                self.all_nodes.append(callee_node)
                span.callee = callee_node
            else:
                span.callee = self.all_nodes[self.all_nodes.index(callee_node)]

        print('call graph span number:', len(self.all_spans), ' call graph node number:', len(self.all_nodes))

        for index, node in enumerate(self.all_nodes):
            node.callgraph_index = index

    def generate_adjacency_matrix(self):
        nodes_number = len(self.all_nodes)
        for i in range(0, nodes_number):
            temp_list = [None]*nodes_number
            self.adjancy_matrix.append(temp_list)

        for span in self.all_spans:
            temp_caller_node = span.get_caller()
            temp_callee_node = span.get_callee()

            caller_node_index = temp_caller_node.callgraph_index
            callee_node_index = temp_callee_node.callgraph_index

            self.adjancy_matrix[caller_node_index][callee_node_index] = span

        count = 0
        for row in range(0, nodes_number):
            for col in range(0, nodes_number):
                if self.adjancy_matrix[row][col]!=None:
                    count = count + 1

    def get_root_cause_server_list(self, root_cause_list):

        root_cause_list = sorted(root_cause_list, key=lambda x: x.root_score, reverse=True)
        root_cause_server_dict = {}
        for root_cause in root_cause_list:
            if root_cause_server_dict.get(root_cause.turple[0]) == None:
                root_cause_server_dict[root_cause.turple[0]] = []
            root_cause_server_dict[root_cause.turple[0]].append(root_cause)
        root_cause_server_list = []
        for server, temp_root_cause_list in root_cause_server_dict.items():
            root_cause_server = Root_Cause_Server(server, temp_root_cause_list)
            root_cause_server_list.append(root_cause_server)
        
        def cmp(root_cause_server1, root_cause_server2):
            if root_cause_server1.root_cause_number < root_cause_server2.root_cause_number:
                return 1
            elif root_cause_server1.root_cause_number == root_cause_server2.root_cause_number:
                if root_cause_server1.average_error_rate < root_cause_server2.average_error_rate:
                    return 1
                elif root_cause_server1.average_error_rate == root_cause_server2.average_error_rate:
                    if root_cause_server1.max_root_score < root_cause_server2.max_root_score:
                        return 1
                    else:
                        return -1                    
                else:

                    return -1
            else:
                return -1

        root_cause_server_list = sorted(root_cause_server_list, key=cmp_to_key(cmp), reverse=False)
        return root_cause_server_list

def compute_pearsonr_between_two_spans(span1, span2, option):
    if option == 'qpm':
        qpm1 = span1.qpm[alarm_time-30:alarm_time]
        qpm2 = span2.qpm[alarm_time-30:alarm_time]

        data1 = []
        data2 = []

        for point1, point2 in zip(qpm1, qpm2):
            if (not np.isnan(point1)) and (not np.isnan(point2)):
                data1.append(point1)
                data2.append(point2)

        if len(data1) <= 2:
            return 0.0

        similarity, _ = pearsonr(data1, data2)
        return abs(similarity)


    elif option == 'ec':
        ec1 = span1.ec[alarm_time-30:alarm_time]
        ec2 = span2.ec[alarm_time-30:alarm_time]

        data1 = []
        data2 = []

        for point1, point2 in zip(ec1, ec2):
            if (not np.isnan(point1)) and (not np.isnan(point2)):
                data1.append(point1)
                data2.append(point2)

        if len(data1) <= 2:
            return 0.0

        similarity, _ = pearsonr(data1, data2)
        return abs(similarity)


    elif option == 'rt':
        rt1 = span1.rt[alarm_time-30:alarm_time]
        rt2 = span2.rt[alarm_time-30:alarm_time]

        data1 = []
        data2 = []

        for point1, point2 in zip(rt1, rt2):
            if (not np.isnan(point1)) and (not np.isnan(point2)):
                data1.append(point1)
                data2.append(point2)

        if len(data1) <= 2:
            return 0.0

        similarity, _ = pearsonr(data1, data2)
        return abs(similarity)

def anomaly_detection_for_one_span(span):

    caller_turple = span.get_caller().get_turple()
    callee_turple = span.get_callee().get_turple()

    metric1 = None
    metric7 = None

    caller_callee_turple = caller_turple + callee_turple
    if caller_callee1.get(caller_callee_turple) != None:
        metric1 = caller_callee1[caller_callee_turple]
    if caller_callee7.get(caller_callee_turple) != None:
        metric7 = caller_callee7[caller_callee_turple]

    if metric1 == None or metric7 == None:
        return

    span_day_before = Span(caller_turple, callee_turple, metric1)
    span_7days_before = Span(caller_turple, callee_turple, metric7)

    span_day_before.normalize_metric()
    span_7days_before.normalize_metric()

    current_rt = span.rt[alarm_time-10: alarm_time]
    comparison_rt_today = span.rt[alarm_time-70: alarm_time-10]
    comparison_rt_day_before = span_day_before.rt[alarm_time-60: alarm_time]
    comparison_rt_7days_before = span_7days_before.rt[alarm_time-60: alarm_time]

    rt_detection = RT_Detection(current_rt, comparison_rt_today, comparison_rt_day_before, comparison_rt_7days_before)
    y = iso_forest.predict([rt_detection.detection()])[0]
    if y==-1:
        span.rt_anomaly = True
        span.rt_beta = 1.0
    else:
        span.rt_anomaly = False
        span.rt_beta=0.0

    current_ec = span.ec[alarm_time-10: alarm_time]
    comparison_ec_today = span.ec[alarm_time-70:alarm_time-10]
    comparison_ec_day_before = span_day_before.ec[alarm_time-60: alarm_time]
    comparison_ec_7days_before = span_7days_before.ec[alarm_time-60: alarm_time]
    exceptions_ec = [-1] * 10

    anomaly_detection_compute_95(exceptions_ec, comparison_ec_today, current_ec, 1)
    anomaly_detection_compute_95(exceptions_ec, comparison_ec_day_before, current_ec, 1)
    anomaly_detection_compute_95(exceptions_ec, comparison_ec_7days_before, current_ec, 1)

    ec_valid = 10 - exceptions_ec.count(-1)
    if ec_valid != 0:
        if 1.0*exceptions_ec.count(1) / (10-exceptions_ec.count(-1)) > threshold:
            span.ec_anomaly = True
            span.ec_beta = 1.0
        else:
            span.ec_beta = 0.0

def ninty_five(comparison):
    data_list = []
    for i in comparison:
        if not np.isnan(i):
            data_list.append(i)
    data_list = sorted(data_list, reverse=True)
    length = len(data_list)
    min_index = math.ceil(0.95 * length)
    max_index = math.ceil(0.05 * length)
    if min_index >= len(data_list):
        min_index = len(data_list) - 1
    return (data_list[min_index], data_list[max_index])

def data_valid(data_list):
    count = 0
    for point in data_list:
        if not np.isnan(point):
            count = count + 1
    return count > 5

def anomaly_detection_compute_95(exceptions, comparison, current, kind):
    if (not data_valid(comparison)) or (not data_valid(current)):
        return

    min, max = ninty_five(comparison)
    for index, date_point in enumerate(current):
         if not np.isnan(current[index]):
                exceptions[index] = 0
                if kind == 0:
                    if current[index]< min or current[index] > max:
                        exceptions[index] = 1
                else:
                    if current[index] > max:
                        exceptions[index] = 1

def split_data(data):
    time_list = [np.nan]*1440
    data_points = data.split(',')

    for data_point in data_points:
        time_list[int(data_point.split(':')[0])] = float(data_point.split(':')[1])

    return time_list

def flex_similarity_pruning(downstream_span, upstream_spans):
    pruning_list = Regression_Pruning(downstream_span, upstream_spans)
    return pruning_list.real_upstream_span_list

def merge_dict(dic1, dic2):
    for key, value in dic2.items():
        if key in dic1:
            dic1[key].extend(value)
        else:
            dic1[key] = value

def read_one_file(lock, path, file, caller_data_local, callee_data_local, caller_callee_local):
    thread_caller_data = {}
    thread_callee_data = {}
    thread_caller_callee = {}

    if file.startswith('part'):
        file_path = path+file
        temp_file = pd.read_csv(file_path, sep='|')
        for i, line in temp_file.iterrows():
            cur_node = (line[1], line[2], line[3], line[4],
                        line[5], line[6], line[7], line[8])
            if thread_caller_data.get((line[1], line[2], line[3], line[4])) == None:
                thread_caller_data[(
                    line[1], line[2], line[3], line[4])] = list()
            thread_caller_data[(line[1], line[2], line[3],
                                line[4])].append(cur_node)

            if thread_callee_data.get((line[5], line[6], line[7], line[8])) == None:
                thread_callee_data[(
                    line[5], line[6], line[7], line[8])] = list()
            thread_callee_data[(line[5], line[6], line[7],
                                line[8])].append(cur_node)

            thread_caller_callee[cur_node] = [
                line[9], line[10], line[12], line[13]]
    lock.acquire()
    merge_dict(caller_data_local, thread_caller_data)
    merge_dict(callee_data_local, thread_callee_data)
    merge_dict(caller_callee_local, thread_caller_callee)
    lock.release()

def read_files(path):
    temp_caller_data = {}
    temp_callee_data = {}
    temp_caller_callee = {}

    files = os.listdir(path)
    threads_local = []
    lock = threading.Lock()
    for file in files:
        thread = threading.Thread(target=read_one_file, args=(
            lock, path, file, temp_caller_data, temp_callee_data, temp_caller_callee))
        threads_local.append(thread)
        thread.start()

    for thread in threads_local:
        thread.join()

    return (temp_caller_data, temp_callee_data, temp_caller_callee)

def read_one_file_past(lock, path, file, caller_callee_local):
    thread_caller_callee = {}

    if file.startswith('part'):
        file_path = path+file
        temp_file = pd.read_csv(file_path, sep='|')
        for i, line in temp_file.iterrows():
            cur_node = (line[1], line[2], line[3], line[4],
                        line[5], line[6], line[7], line[8])

            thread_caller_callee[cur_node] = [
                line[9], line[10], line[12], line[13]]
    lock.acquire()
    merge_dict(caller_callee_local, thread_caller_callee)
    lock.release()

def read_files_past(path):
    temp_caller_callee = {}

    files = os.listdir(path)
    threads_local = []
    lock = threading.Lock()
    for file in files:
        thread = threading.Thread(target=read_one_file_past, args=(
            lock, path, file, temp_caller_callee))
        threads_local.append(thread)
        thread.start()

    for thread in threads_local:
        thread.join()

    return temp_caller_callee

def get_uplink_spans(span, entry_span):
    temp_spans = []
    if callee_data.get(span.get_caller()) != None:
        for caller_callee_turple in callee_data[span.get_caller()]:
            caller = (caller_callee_turple[0], caller_callee_turple[1],
                      caller_callee_turple[2], caller_callee_turple[3])
            callee = (caller_callee_turple[4], caller_callee_turple[5],
                      caller_callee_turple[6], caller_callee_turple[7])
            metric = caller_callee[caller_callee_turple]
            new_span = Span(caller, callee, metric, entry_span=entry_span)
            new_span.normalize_metric()
            # if (new_span not in temp_spans) and (new_span not in uplink_cache_spans):
            if new_span.metric_valid_30_mins_before_alarm(alarm_time):
                temp_spans.append(new_span)
    return temp_spans

def get_downlink_spans(span, entry_span):
    temp_spans = []
    if caller_data.get(span.get_callee()) != None:
        for caller_callee_turple in caller_data[span.get_callee()]:
            caller = (caller_callee_turple[0], caller_callee_turple[1],
                      caller_callee_turple[2], caller_callee_turple[3])
            callee = (caller_callee_turple[4], caller_callee_turple[5],
                      caller_callee_turple[6], caller_callee_turple[7])
            metric = caller_callee[caller_callee_turple]

            new_span = Span(caller, callee, metric, entry_span=entry_span)
            new_span.normalize_metric()

            if new_span.metric_valid_30_mins_before_alarm(alarm_time):
                if (caller, callee) not in cache_span_dict.keys():
                    temp_spans.append(new_span)
                    temp_upstream_spans = get_uplink_spans(span, entry_span)
                    for temp_up_span in temp_upstream_spans:
                        temp_up_span.extra_span = True
                    global extra_span_list
                    extra_span_list.extend(temp_upstream_spans)
                    cache_span_dict[(caller, callee)] = 0
    return temp_spans

def extend_entry_span(caller_spans, callee_spans):
    downlink_cache_spans = []
    
    for span in caller_spans:
        downlink_cache_spans.extend(get_downlink_spans(span, span))

    while len(downlink_cache_spans) != 0:
        top_span = downlink_cache_spans[0]
        downlink_cache_spans.pop(0)
        downlink_spans.append(top_span)

        downlink_cache_spans.extend(get_downlink_spans(top_span, top_span.entry_span))

    all_related_spans = []
    entry_spans = []

    entry_spans.extend(caller_spans)
    entry_spans.extend(callee_spans)

    all_related_spans.extend(entry_spans)
    all_related_spans.extend(uplink_spans)
    all_related_spans.extend(downlink_spans)

    return (entry_spans, list(set(all_related_spans)))

def get_downstream_spans(cg, span):
    
    callee_index = span.callee.callgraph_index
    temp_span_list = []
    for col in range(0, len(cg.all_nodes)):
        if cg.adjancy_matrix[callee_index][col] != None and cg.temp_cache_span_dict.get(cg.adjancy_matrix[callee_index][col]) == None:
            cg.adjancy_matrix[callee_index][col].temp_exploration_upstream_span = span
            temp_span_list.append(cg.adjancy_matrix[callee_index][col])
            cg.temp_cache_span_dict[cg.adjancy_matrix[callee_index][col]] = 1
    return temp_span_list

def get_upstream_spans(cg, span):
    caller_index = span.caller.callgraph_index
    temp_span_list = []
    for row in range(0, len(cg.all_nodes)):
        if cg.adjancy_matrix[row][caller_index] != None:
            temp_span_list.append(cg.adjancy_matrix[row][caller_index])
    return temp_span_list

def root_cause_exploration(cg):
    cg.qpm_root_cause_list = []
    cg.ec_root_cause_list = []
    cg.rt_root_cause_list = []

    global explored_ec_anomaly_entry_spans
    global explored_rt_anomaly_entry_spans

    for span in cg.all_spans:
        span.temp_exploration_upstream_span = None
        span.compute_pearsonr_to_entry_span()

    ec_anomaly_entry_spans = cg.ec_anomaly_entry_spans
    rt_anomaly_entry_spans = cg.rt_anomaly_entry_spans

    for entry_span in ec_anomaly_entry_spans:
        if entry_span not in explored_ec_anomaly_entry_spans:
            explored_ec_anomaly_entry_spans.append(entry_span)
        else:
            continue

        cache_span_list = []
        cg.temp_cache_span_dict = {}
        temp_span_list = get_downstream_spans(cg, entry_span)
        flag = False
        for temp_span in temp_span_list:
            if temp_span.ec_anomaly:
                temp_similarity = compute_pearsonr_between_two_spans(entry_span, temp_span, 'ec')
                if temp_similarity > microhecl_threshold:
                    cache_span_list.append(temp_span)
                else:
                    root_cause = Root_Cause(entry_span, entry_span.callee.get_turple(), entry_span.ec_similarity)
                    cg.ec_root_cause_list.append(root_cause)

                flag = True

        if not flag:
            root_cause = Root_Cause(entry_span, entry_span.callee.get_turple(), entry_span.ec_similarity)
            cg.ec_root_cause_list.append(root_cause)

        while len(cache_span_list)>0:
            top_span = cache_span_list[0]
            cache_span_list.pop(0)

            if top_span.is_entry and (top_span in explored_ec_anomaly_entry_spans):
                continue

            if top_span.is_entry and (top_span not in explored_ec_anomaly_entry_spans) and (top_span.temp_exploration_upstream_span == None):
                explored_ec_anomaly_entry_spans.append(top_span)
                temp_span_list = get_downstream_spans(cg, top_span)
                flag = False
                for temp_span in temp_span_list:
                    if temp_span.ec_anomaly:
                        flag = True
                        temp_similarity = compute_pearsonr_between_two_spans(top_span, temp_span, 'ec')
                        if temp_similarity > microhecl_threshold:
                            cache_span_list.append(temp_span)
                        else:
                            root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.ec_similarity)
                            cg.ec_root_cause_list.append(root_cause)

                if not flag:
                    root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.ec_similarity)
                    cg.ec_root_cause_list.append(root_cause)
                

            if top_span.is_entry and (top_span not in explored_ec_anomaly_entry_spans) and (top_span.temp_exploration_upstream_span != None):
                explored_ec_anomaly_entry_spans.append(top_span)

            
            temp_upstream_span_list = get_upstream_spans(cg, top_span)
            if len(temp_upstream_span_list) > 1:
                real_upstream_span_list = flex_similarity_pruning(top_span, temp_upstream_span_list)

                if top_span.temp_exploration_upstream_span in real_upstream_span_list:
                    temp_span_list = get_downstream_spans(cg, top_span)
                    flag = False
                    for temp_span in temp_span_list:
                        if temp_span.ec_anomaly:

                            temp_similarity = compute_pearsonr_between_two_spans(top_span, temp_span, 'ec')
                            if temp_similarity > microhecl_threshold:
                                cache_span_list.append(temp_span)
                            else:
                                root_cause = Root_Cause(top_span, top_span.callee.get_turple(),top_span.ec_similarity)
                                cg.ec_root_cause_list.append(root_cause)
                            flag = True

                    if not flag:
                        root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.ec_similarity)
                        cg.ec_root_cause_list.append(root_cause)

                else:
                    root_cause = Root_Cause(top_span.temp_exploration_upstream_span, top_span.temp_exploration_upstream_span.callee.get_turple(), top_span.temp_exploration_upstream_span.ec_similarity)
                    cg.ec_root_cause_list.append(root_cause)

            else:
                temp_span_list = get_downstream_spans(cg, top_span)
                flag = False
                for temp_span in temp_span_list:
                    if temp_span.ec_anomaly:
                        temp_similarity = compute_pearsonr_between_two_spans(top_span, temp_span, 'ec')
                        if temp_similarity > microhecl_threshold:
                            cache_span_list.append(temp_span)
                        else:
                            root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.ec_similarity)
                            cg.ec_root_cause_list.append(root_cause)
                        flag = True

                if not flag:
                    root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.ec_similarity)
                    cg.ec_root_cause_list.append(root_cause)

    
    for span in cg.all_spans:
        span.temp_exploration_upstream_span = None

    for entry_span in rt_anomaly_entry_spans:
        if entry_span not in explored_rt_anomaly_entry_spans:
            explored_rt_anomaly_entry_spans.append(entry_span)
        else:
            continue
        cache_span_list = []
        cg.temp_cache_span_dict = {}
        temp_span_list = get_downstream_spans(cg, entry_span)
        flag = False
        for temp_span in temp_span_list:
            if temp_span.rt_anomaly:
                flag = True

                temp_similarity = compute_pearsonr_between_two_spans(entry_span, temp_span, 'rt')
                if temp_similarity > microhecl_threshold:
                    cache_span_list.append(temp_span)
                else:
                    root_cause = Root_Cause(entry_span, entry_span.callee.get_turple(), entry_span.rt_similarity)
                    cg.rt_root_cause_list.append(root_cause)

        if not flag:
            root_cause = Root_Cause(entry_span, entry_span.callee.get_turple(), entry_span.rt_similarity)
            cg.rt_root_cause_list.append(root_cause)


        while len(cache_span_list)>0:
            top_span = cache_span_list[0]       
            cache_span_list.pop(0)
            

            if top_span.is_entry and top_span in explored_rt_anomaly_entry_spans:
                continue

            if top_span.is_entry and (top_span not in explored_rt_anomaly_entry_spans) and (top_span.temp_exploration_upstream_span == None):
                explored_rt_anomaly_entry_spans.append(top_span)
                temp_span_list = get_downstream_spans(cg, top_span)
                flag = False
                for temp_span in temp_span_list:
                    if temp_span.rt_anomaly:
                        flag = True

                        temp_similarity = compute_pearsonr_between_two_spans(top_span, temp_span, 'rt')
                        if temp_similarity > microhecl_threshold:
                            cache_span_list.append(temp_span)
                        else:
                            root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.rt_similarity)
                            cg.rt_root_cause_list.append(root_cause)

                if not flag:
                    root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.rt_similarity)
                    cg.rt_root_cause_list.append(root_cause)

                continue

            if top_span.is_entry and (top_span not in explored_rt_anomaly_entry_spans) and (top_span.temp_exploration_upstream_span != None):
                explored_rt_anomaly_entry_spans.append(top_span)

            temp_upstream_span_list = get_upstream_spans(cg, top_span)
            if len(temp_upstream_span_list) > 1:
                real_upstream_span_list = flex_similarity_pruning(top_span, temp_upstream_span_list)

                if top_span.temp_exploration_upstream_span in real_upstream_span_list:
                    temp_span_list = get_downstream_spans(cg, top_span)
                    flag = False
                    for temp_span in temp_span_list:
                        if temp_span.rt_anomaly:
                            flag = True

                            temp_similarity = compute_pearsonr_between_two_spans(top_span, temp_span, 'rt')
                            if temp_similarity > microhecl_threshold:
                                cache_span_list.append(temp_span)
                            else:
                                root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.rt_similarity)
                                cg.rt_root_cause_list.append(root_cause)

                    if not flag:
                        root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.rt_similarity)
                        cg.rt_root_cause_list.append(root_cause)

                else:
                    root_cause = Root_Cause(top_span.temp_exploration_upstream_span, top_span.temp_exploration_upstream_span.callee.get_turple(), top_span.temp_exploration_upstream_span.rt_similarity)
                    cg.rt_root_cause_list.append(root_cause)

            else:
                temp_span_list = get_downstream_spans(cg, top_span)
                flag = False
                for temp_span in temp_span_list:
                    if temp_span.rt_anomaly:
                        flag = True
                        temp_similarity = compute_pearsonr_between_two_spans(top_span, temp_span, 'rt')
                        if temp_similarity>microhecl_threshold:
                            cache_span_list.append(temp_span)
                        else:
                            root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.rt_similarity)
                            cg.rt_root_cause_list.append(root_cause)

                if not flag:
                    root_cause = Root_Cause(top_span, top_span.callee.get_turple(), top_span.rt_similarity)
                    cg.rt_root_cause_list.append(root_cause)


    cg.qpm_root_cause_server_list = cg.get_root_cause_server_list(cg.qpm_root_cause_list)
    cg.ec_root_cause_server_list = cg.get_root_cause_server_list(cg.ec_root_cause_list)
    cg.rt_root_cause_server_list = cg.get_root_cause_server_list(cg.rt_root_cause_list)
    cg.root_cause_list = cg.qpm_root_cause_list + cg.ec_root_cause_list + cg.rt_root_cause_list
    cg.root_cause_server_list = cg.get_root_cause_server_list(cg.root_cause_list)

    print('QPM root cause server number: ', len(cg.qpm_root_cause_server_list))
    for root_cause_server in cg.qpm_root_cause_server_list:
        print('server:', root_cause_server)
    print('############################################')

    print('EC root cause server number: ', len(cg.ec_root_cause_server_list))
    for root_cause_server in cg.ec_root_cause_server_list:
        print('server:', root_cause_server)
    print('############################################')

    print('RT root cause server number: ', len(cg.rt_root_cause_server_list))
    for root_cause_server in cg.rt_root_cause_server_list:
        print('server:', root_cause_server)
    print('############################################')

    print('ALL root cause server number: ', len(cg.root_cause_server_list))
    for root_cause_server in cg.root_cause_server_list:
        print('server:', root_cause_server)

if __name__ == '__main__':

    # ec anomaly detection threshold
    threshold = 0.10
    # regression pruning threshold
    regression_threshold = 0.005
    # similarity pruning threshold
    microhecl_threshold = 0.7
    regression_param = sys.maxsize

    similarity_arrays = []
    similarity_array_dict = {}

    # anomaly detection model
    iso_forest = pickle.load(open('','rb'))
    explored_ec_anomaly_entry_spans = []
    explored_rt_anomaly_entry_spans = []
    
    case_number = int(sys.argv[1])
    cache_span_dict = {}
    extra_span_list = []


    # the SLO alarm server
    item_server = ''
    # the slo alarm time
    slo_time = ''
    root_cause_server_str = ''

    alarm_times = slo_time.split()[1].split(':')
    alarm_time = int(alarm_times[0]) * 60 + int(alarm_times[1])
    date_str_list = slo_time.split()[0].split('/')
    date_str = date_str_list[0] + date_str_list[1] + date_str_list[2]
    alarm_date = datetime.datetime.strptime(date_str, '%Y%m%d')

    path_today = './app_opsdatagovern_aiops_export_caller_min_monitor_di/' + \
        alarm_date.strftime('%Y%m%d') + '/'
    path_day_before = './app_opsdatagovern_aiops_export_caller_min_monitor_di/' + \
        (alarm_date-datetime.timedelta(days=1)).strftime('%Y%m%d') + '/'
    path_7days_before = './app_opsdatagovern_aiops_export_caller_min_monitor_di/' + \
        (alarm_date-datetime.timedelta(days=7)).strftime('%Y%m%d') + '/'


    caller_data, callee_data, caller_callee = read_files(path_today)
    caller_callee1 = read_files_past(path_day_before)
    caller_callee7 = read_files_past(path_7days_before)


    uplink_spans = []
    downlink_spans = []
    entry_spans_as_callee = []
    entry_spans_as_caller = []


    for key, caller_callee_turples in caller_data.items():
        if key[0] == item_server:
            for caller_callee_turple in caller_callee_turples:

                caller = (caller_callee_turple[0], caller_callee_turple[1],
                        caller_callee_turple[2], caller_callee_turple[3])
                callee = (caller_callee_turple[4], caller_callee_turple[5],
                        caller_callee_turple[6], caller_callee_turple[7])
                metric = caller_callee[caller_callee_turple]
                span = Span(caller, callee, metric, is_entry=True)
                span.normalize_metric()
                if span.metric_valid_30_mins_before_alarm(alarm_time):
                    entry_spans_as_caller.append(span)
                else:
                    pass
        else:
            continue

    for key, caller_callee_turples in callee_data.items():
        if key[0] == item_server:
            for caller_callee_turple in caller_callee_turples:

                caller = (caller_callee_turple[0], caller_callee_turple[1],
                        caller_callee_turple[2], caller_callee_turple[3])
                callee = (caller_callee_turple[4], caller_callee_turple[5],
                        caller_callee_turple[6], caller_callee_turple[7])
                metric = caller_callee[caller_callee_turple]
                span = Span(caller, callee, metric, is_entry=True)
                span.normalize_metric()
                if span.metric_valid_30_mins_before_alarm(alarm_time):
                    entry_spans_as_callee.append(span)
                else:
                    pass
        else:
            continue


    callgraph_entry_spans, callgraph_all_spans = extend_entry_span(entry_spans_as_caller, entry_spans_as_callee)
    extra_span_list=list(set(extra_span_list))
    callgraph_all_spans.extend(extra_span_list)
    callgraph_all_spans=list(set(callgraph_all_spans))

    callgraph = Callgraph(callgraph_all_spans, callgraph_entry_spans)  
    root_cause_exploration(callgraph)

    line_to_write = ['case '+str(case_number)]

    flag_ec = False
    flag_rt = False
    flag_all = False

    for index, root_cause_server in enumerate(callgraph.ec_root_cause_server_list):
        if root_cause_server.server == root_cause_server_str:
            print('found root cause in ec:', index +1,'of',len(callgraph.ec_root_cause_server_list))
            flag_ec = True
            line_to_write.append(str(index+1)+'/'+str(len(callgraph.ec_root_cause_server_list)))

    if flag_ec == False:
        if len(callgraph.ec_root_cause_server_list) == 0:
            line_to_write.append('none')
            print('ec no root cause')
        else:
            print('ec not exist in',len(callgraph.ec_root_cause_server_list))
            line_to_write.append('no')
    
    for index, root_cause_server in enumerate(callgraph.rt_root_cause_server_list):
        if root_cause_server.server == root_cause_server_str:
            print('found root cause in rt:', index +1,'of',len(callgraph.rt_root_cause_server_list))
            flag_rt = True
            line_to_write.append(str(index+1)+'/'+str(len(callgraph.rt_root_cause_server_list)))
    if flag_rt == False:
        if len(callgraph.rt_root_cause_server_list) == 0:
            print('rt no root cause')
            line_to_write.append('none')
        else:
            print('rt not exist in',len(callgraph.rt_root_cause_server_list))
            line_to_write.append('no')
        
    for index, root_cause_server in enumerate(callgraph.root_cause_server_list):
        if root_cause_server.server == root_cause_server_str:
            print('found root cause in all:', index +1,'of',len(callgraph.root_cause_server_list))
            flag_all = True
            line_to_write.append(str(index+1)+'/'+str(len(callgraph.root_cause_server_list)))
    if flag_all == False:
        if len(callgraph.root_cause_server_list) == 0:
            print('all no root cause')
            line_to_write.append('none')
        else:
            print('all not exist in',len(callgraph.root_cause_server_list))
            line_to_write.append('no')

    csv_file = open('result.csv', 'a')
    writer = csv.writer(csv_file)
    writer.writerow(line_to_write)
    csv_file.close()
