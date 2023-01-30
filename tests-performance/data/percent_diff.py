import numpy as np

tests = [
    ('rodeo-data/enum_results_cvc5.csv', 'rodeo-data/enum_results_z3.csv'),
    ('rodeo-data/string_wc_results_cvc5.csv',
     'rodeo-data/string_wc_results_z3.csv'),
]

data_size = [{}, {}]
data_load = [{}, {}]
smt_encoding = [{}, {}]
p_impy_q = [{}, {}]
q_imply_p = [{}]

# load the raw data
for idx, test in enumerate(tests):
    # print(f'test[0]: {test[0]}')
    if idx == 0:
        data_size[idx]['cvc'], \
            data_load[idx]['cvc'], \
            smt_encoding[idx]['cvc'], \
            p_impy_q[idx]['cvc'], \
            q_imply_p[idx]['cvc'] = np.loadtxt(
                test[0], delimiter=',', unpack=True)

        data_size[idx]['z3'], \
            data_load[idx]['z3'], \
            smt_encoding[idx]['z3'], \
            p_impy_q[idx]['z3'], \
            q_imply_p[idx]['z3'] = np.loadtxt(
                test[1], delimiter=',', unpack=True)

    if idx == 1:
        data_size[idx]['cvc'], \
            data_load[idx]['cvc'], \
            smt_encoding[idx]['cvc'], \
            p_impy_q[idx]['cvc'] = np.loadtxt(
                test[0], delimiter=',', unpack=True)

        data_size[idx]['z3'], \
            data_load[idx]['z3'], \
            smt_encoding[idx]['z3'], \
            p_impy_q[idx]['z3'] = np.loadtxt(
                test[1], delimiter=',', unpack=True)


# ENUM -------
# compute the averages for each n
avgs_cvc_enum = {}
avgs_z3_enum = {}
cvc_tot = 0
z3_tot = 0
num_samples = 0
idx = 0
current_n = data_size[0]['cvc'][0]
for n in data_size[0]['cvc']:
    # found a new sample size; compute the current avg and reset the counters
    if n > current_n:
        avgs_cvc_enum[current_n] = cvc_tot / num_samples
        avgs_z3_enum[current_n] = z3_tot / num_samples
        num_samples = 0
        cvc_tot = 0
        z3_tot = 0
        current_n = n
        # we don't have measurements for z3 for n > 4000
        if n > 4000:
            break

    # increment counters and totals
    num_samples += 1
    # add up all the individual times for each sample
    z3_tot += data_load[0]['z3'][idx] + smt_encoding[0]['z3'][idx] + \
        p_impy_q[0]['z3'][idx] + q_imply_p[0]['z3'][idx]
    cvc_tot += data_load[0]['cvc'][idx] + smt_encoding[0]['cvc'][idx] + \
        p_impy_q[0]['cvc'][idx] + q_imply_p[0]['cvc'][idx]
    idx += 1

percent_diff_enums = {}
percent_diff_enums2 = {}
for n, avg in avgs_cvc_enum.items():
    percent_diff_enums[n] = (
        avgs_z3_enum[n] - avgs_cvc_enum[n]) / avgs_z3_enum[n] * 100
    percent_diff_enums2[n] = (avgs_cvc_enum[n] / avgs_z3_enum[n]) * 100


# STRING ------
# compute the averages for each n
avgs_cvc_string = {}
avgs_z3_string = {}
cvc_tot = 0
z3_tot = 0
num_samples = 0
idx = 0
current_n = data_size[1]['cvc'][0]
for n in data_size[1]['cvc']:
    # found a new sample size; compute the current avg and reset the counters
    if n > current_n:
        avgs_cvc_string[current_n] = cvc_tot / num_samples
        avgs_z3_string[current_n] = z3_tot / num_samples
        num_samples = 0
        cvc_tot = 0
        z3_tot = 0
        current_n = n
        # we don't have measurements for z3 for n > 4000
        if n > 4000:
            break

    # increment counters and totals
    num_samples += 1
    # add up all the individual times for each sample
    z3_tot += data_load[1]['z3'][idx] + smt_encoding[1]['z3'][idx] + \
        p_impy_q[1]['z3'][idx]
    cvc_tot += data_load[1]['cvc'][idx] + smt_encoding[1]['cvc'][idx] + \
        p_impy_q[1]['cvc'][idx]
    idx += 1

percent_diff_string = {}
percent_diff_string2 = {}
for n, avg in avgs_cvc_string.items():
    percent_diff_string[n] = (
        avgs_cvc_string[n] - avgs_z3_string[n]) / avgs_z3_string[n] * 100
    percent_diff_string2[n] = (avgs_z3_string[n] / avgs_cvc_string[n]) * 100
