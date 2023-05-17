import numpy as np
from matplotlib import pyplot as plt
import csv

def plot_enum_cvc5():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    q_imply_p = []

    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('enum_results_cvc5.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    s4 = plt.scatter(data_size, q_imply_p,c='c')
    plt.legend([s1, s2, s3, s4], ['cvc5 Data load', 'cvc5 SMT Encoding', 'cvc5 P => Q', 'cvc5 Q => P'])

    plt.title('StringEnum Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()

def plot_enum_z3():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    q_imply_p = []
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('enum_results_z3.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    s4 = plt.scatter(data_size, q_imply_p,c='c')
    plt.legend([s1, s2, s3, s4], ['cvc5 Data load', 'cvc5 SMT Encoding', 'cvc5 P => Q', 'cvc5 Q => P'])
    #plt.legend([s1, s2, s3, s4], ['z3 Data load', 'z3 SMT Encoding', 'z3 P => Q', 'z3 Q => P'])
    #plt.title('StringRe with wildcard')
    plt.title('StringEnum Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()

def plot_string_re_wc_cvc5():
    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    #q_imply_p = []
    data_size, data_load, smt_encoding, p_impy_q  = np.loadtxt('string_re_wc_results_cvc5.csv', delimiter=',', unpack=True)
    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    plt.legend([s1,s2,s3],['cvc5 Data load','cvc5 SMT Encoding','cvc5 P => Q' ])
    #plt.scatter(data_size, q_imply_p,c='c')
    #plt.title('StringRe with wildcard')
    plt.title('StringRe with WildCard Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()

def plot_string_re_wc_z3():
    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    #q_imply_p = []
    data_size, data_load, smt_encoding, p_impy_q  = np.loadtxt('string_re_wc_results_z3.csv', delimiter=',', unpack=True)
    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    plt.legend([s1,s2,s3],['z3 Data load','z3 SMT Encoding','z3 P => Q' ])
    #plt.scatter(data_size, q_imply_p,c='c')
    #plt.title('StringRe with wildcard')
    plt.title('StringRe with WildCard Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.xscale("log")
    plt.yscale("log")
    plt.show()


def plot_enum_with_stats_z3():
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p = np.loadtxt('enum_results_z3.csv', delimiter=',',
                                                                         unpack=True)
    # plot means with error bars (standard deviation)
    idx = 0
    data_size_vals = []
    data_load_means = []
    data_load_stds = []
    smt_encode_means = []
    smt_encode_stds = []
    p_impy_q_means = []
    p_impy_q_stds = []
    q_impy_p_means = []
    q_impy_p_stds = []
    while idx < len(data_size):
        dl_temp = []
        se_temp = []
        pq_temp = []
        qp_temp = []
        current_data_size = data_size[idx]
        data_size_vals.append(current_data_size)
        while idx < len(data_size) and data_size[idx] == current_data_size:
            dl_temp.append(data_load[idx])
            se_temp.append(smt_encoding[idx])
            pq_temp.append(p_impy_q[idx])
            qp_temp.append(q_imply_p[idx])
            idx += 1
        # compute means and standard deviations
        data_load_means.append(np.mean(dl_temp))
        data_load_stds.append(np.std(dl_temp))

        smt_encode_means.append(np.mean(se_temp))
        smt_encode_stds.append(np.std(se_temp))

        p_impy_q_means.append(np.mean(pq_temp))
        p_impy_q_stds.append(np.std(pq_temp))

        q_impy_p_means.append(np.mean(qp_temp))
        q_impy_p_stds.append(np.std(qp_temp))
    # create plots of means with error bars based on std
    plt.title('Enum Performance Scalability (Log/Log Scale)')
    plt.xlabel('Data size (n)')
    plt.ylabel('Times (in seconds)')
    s1 = plt.scatter(data_size_vals, data_load_means, color='r')
    plt.errorbar(data_size_vals, data_load_means, yerr=data_load_stds, fmt="o", color='r')
    s2 = plt.scatter(data_size_vals, smt_encode_means, color='b')
    plt.errorbar(data_size_vals, smt_encode_means, yerr=smt_encode_stds, fmt="o", color='b')
    s3 = plt.scatter(data_size_vals, p_impy_q_means, color='g')
    plt.errorbar(data_size_vals, p_impy_q_means, yerr=p_impy_q_stds, fmt="o", color='g')
    s4 = plt.scatter(data_size_vals, q_impy_p_means, color='c')
    plt.errorbar(data_size_vals, q_impy_p_means, yerr=q_impy_p_stds, fmt='o', color='c')
    plt.legend([s1, s2, s3, s4], ['Data load', 'SMT Encoding', 'P => Q', 'Q => P'])

    # Set log scales
    ax = plt.gca()
    ax.set_xscale("log")
    ax.set_yscale("log")

    # output and save
    plt.show()
    plt.savefig('z3_enum_perf_stats.png')

def plot_enum_with_stats_cvc5():
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p = np.loadtxt('enum_results_cvc5.csv', delimiter=',',
                                                                         unpack=True)
    # plot means with error bars (standard deviation)
    idx = 0
    data_size_vals = []
    data_load_means = []
    data_load_stds = []
    smt_encode_means = []
    smt_encode_stds = []
    p_impy_q_means = []
    p_impy_q_stds = []
    q_impy_p_means = []
    q_impy_p_stds = []
    while idx < len(data_size):
        dl_temp = []
        se_temp = []
        pq_temp = []
        qp_temp = []
        current_data_size = data_size[idx]
        data_size_vals.append(current_data_size)
        while idx < len(data_size) and data_size[idx] == current_data_size:
            dl_temp.append(data_load[idx])
            se_temp.append(smt_encoding[idx])
            pq_temp.append(p_impy_q[idx])
            qp_temp.append(q_imply_p[idx])
            idx += 1
        # compute means and standard deviations
        data_load_means.append(np.mean(dl_temp))
        data_load_stds.append(np.std(dl_temp))

        smt_encode_means.append(np.mean(se_temp))
        smt_encode_stds.append(np.std(se_temp))

        p_impy_q_means.append(np.mean(pq_temp))
        p_impy_q_stds.append(np.std(pq_temp))

        q_impy_p_means.append(np.mean(qp_temp))
        q_impy_p_stds.append(np.std(qp_temp))
    # create plots of means with error bars based on std
    plt.title('Enum Performance Scalability (Log/Log Scale)')
    plt.xlabel('Data size (n)')
    plt.ylabel('Times (in seconds)')
    s1 = plt.scatter(data_size_vals, data_load_means, color='r')
    plt.errorbar(data_size_vals, data_load_means, yerr=data_load_stds, fmt="o", color='r')
    s2 = plt.scatter(data_size_vals, smt_encode_means, color='b')
    plt.errorbar(data_size_vals, smt_encode_means, yerr=smt_encode_stds, fmt="o", color='b')
    s3 = plt.scatter(data_size_vals, p_impy_q_means, color='g')
    plt.errorbar(data_size_vals, p_impy_q_means, yerr=p_impy_q_stds, fmt="o", color='g')
    s4 = plt.scatter(data_size_vals, q_impy_p_means, color='c')
    plt.errorbar(data_size_vals, q_impy_p_means, yerr=q_impy_p_stds, fmt='o', color='c')
    plt.legend([s1, s2, s3, s4], ['Data load', 'SMT Encoding', 'P => Q', 'Q => P'])

    # Set log scales
    ax = plt.gca()
    ax.set_xscale("log")
    ax.set_yscale("log")

    # output and save
    plt.show()
    plt.savefig('cvc5_enum_perf_stats.png')

def plot_string_wc_stats_z3():
    data_size, data_load, smt_encoding, p_impy_q = np.loadtxt('string_wc_results_z3.csv', delimiter=',', unpack=True)
    # plot means with error bars (standard deviation)
    idx = 0
    data_size_vals = []
    data_load_means = []
    data_load_stds = []
    smt_encode_means = []
    smt_encode_stds = []
    p_impy_q_means = []
    p_impy_q_stds = []
    while idx < len(data_size):
        dl_temp = []
        se_temp = []
        pq_temp = []
        current_data_size = data_size[idx]
        data_size_vals.append(current_data_size)
        while idx < len(data_size) and data_size[idx] == current_data_size:
            dl_temp.append(data_load[idx])
            se_temp.append(smt_encoding[idx])
            pq_temp.append(p_impy_q[idx])
            idx += 1
        # compute means and standard deviations
        data_load_means.append(np.mean(dl_temp))
        data_load_stds.append(np.std(dl_temp))

        smt_encode_means.append(np.mean(se_temp))
        smt_encode_stds.append(np.std(se_temp))

        p_impy_q_means.append(np.mean(pq_temp))
        p_impy_q_stds.append(np.std(pq_temp))

    # create plots of means with error bars based on std
    plt.title('String With Wildcard Performance Scalability (Log/Log Scale)')
    plt.xlabel('Data size (n)')
    plt.ylabel('Times (in seconds)')
    s1 = plt.scatter(data_size_vals, data_load_means, color='r')
    plt.errorbar(data_size_vals, data_load_means, yerr=data_load_stds, fmt="o", color='r')
    s2 = plt.scatter(data_size_vals, smt_encode_means, color='b')
    plt.errorbar(data_size_vals, smt_encode_means, yerr=smt_encode_stds, fmt="o", color='b')
    s3 = plt.scatter(data_size_vals, p_impy_q_means, color='g')
    plt.errorbar(data_size_vals, p_impy_q_means, yerr=p_impy_q_stds, fmt="o", color='g')
    plt.legend([s1, s2, s3], ['Data load', 'SMT Encoding', 'P => Q'])

    # Set log scales
    ax = plt.gca()
    ax.set_xscale("log")
    ax.set_yscale("log")

    # output and save
    plt.show()
    plt.savefig('z3_string_wc_perf_stats.png')

def plot_string_wc_stats_cvc5():
    data_size, data_load, smt_encoding, p_impy_q  = np.loadtxt('string_wc_results_cvc5.csv', delimiter=',',
                                                                         unpack=True)
    # plot means with error bars (standard deviation)
    idx = 0
    data_size_vals = []
    data_load_means = []
    data_load_stds = []
    smt_encode_means = []
    smt_encode_stds = []
    p_impy_q_means = []
    p_impy_q_stds = []
    #q_impy_p_means = []
    #q_impy_p_stds = []
    while idx < len(data_size):
        dl_temp = []
        se_temp = []
        pq_temp = []
        qp_temp = []
        current_data_size = data_size[idx]
        data_size_vals.append(current_data_size)
        while idx < len(data_size) and data_size[idx] == current_data_size:
            dl_temp.append(data_load[idx])
            se_temp.append(smt_encoding[idx])
            pq_temp.append(p_impy_q[idx])
            #qp_temp.append(q_imply_p[idx])
            idx += 1
        # compute means and standard deviations
        data_load_means.append(np.mean(dl_temp))
        data_load_stds.append(np.std(dl_temp))

        smt_encode_means.append(np.mean(se_temp))
        smt_encode_stds.append(np.std(se_temp))

        p_impy_q_means.append(np.mean(pq_temp))
        p_impy_q_stds.append(np.std(pq_temp))

       # q_impy_p_means.append(np.mean(qp_temp))
       # q_impy_p_stds.append(np.std(qp_temp))
    # create plots of means with error bars based on std
    plt.title('String with Wildcard Performance Scalability (Log/Log Scale)')
    plt.xlabel('Data size (n)')
    plt.ylabel('Times (in seconds)')
    s1 = plt.scatter(data_size_vals, data_load_means, color='r')
    plt.errorbar(data_size_vals, data_load_means, yerr=data_load_stds, fmt="o", color='r')
    s2 = plt.scatter(data_size_vals, smt_encode_means, color='b')
    plt.errorbar(data_size_vals, smt_encode_means, yerr=smt_encode_stds, fmt="o", color='b')
    s3 = plt.scatter(data_size_vals, p_impy_q_means, color='g')
    plt.errorbar(data_size_vals, p_impy_q_means, yerr=p_impy_q_stds, fmt="o", color='g')
    #s4 = plt.scatter(data_size_vals, q_impy_p_means, color='c')
    #plt.errorbar(data_size_vals, q_impy_p_means, yerr=q_impy_p_stds, fmt='o', color='c')
    plt.legend([s1, s2, s3], ['Data load', 'SMT Encoding', 'P => Q'])

    # Set log scales
    ax = plt.gca()
    ax.set_xscale("log")
    ax.set_yscale("log")

    # output and save
    plt.show()
    plt.savefig('cvc5_string_wc_perf_stats.png')

def plot_enum_combined():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    q_imply_p = []
    #x_data, y_data, z_data = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('enum_results_cvc5.csv', delimiter=',', unpack=True)
    z3_data_size, z3_data_load, z3_smt_encoding, z3_p_impy_q, z3_q_imply_p = np.loadtxt('enum_results_z3.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size[0:136], data_load[0:136],c='r') # data load
    s2 = plt.scatter(data_size[0:136], smt_encoding[0:136],c='b')
    s3 = plt.scatter(data_size[0:136], p_impy_q[0:136],c='g')
    s4 = plt.scatter(data_size[0:136], q_imply_p[0:136],c='c')

    s11 = plt.scatter(z3_data_size, z3_data_load, c='r', marker='+')  # data load
    s21 = plt.scatter(z3_data_size, z3_smt_encoding, c='b', marker='+')
    s31 = plt.scatter(z3_data_size, z3_p_impy_q, c='g', marker='+')
    s41 = plt.scatter(z3_data_size, z3_q_imply_p, c='c', marker='+')
    plt.legend([s1,s2,s3,s4, s11, s21, s31, s41], ['cvc5 Data load', 'cvc5 SMT Encoding', 'cvc5 P => Q', 'cvc5 Q => P', 'z3 Data load', 'z3 SMT Encoding', 'z3 P => Q', 'z3 Q => P'])
    #plt.title('StringRe with wildcard')
    plt.title('StringEnum Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()
