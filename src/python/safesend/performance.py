import matplotlib.pyplot as plt
import csv

def analyze_logs(log_file_path):
    times = []
    throughput = []
    retransmissions = []

    with open(log_file_path, "r") as log_file:
        reader = csv.reader(log_file)
        for row in reader:
            if row[0] == "STATS":
                times.append(float(row[1]))
                throughput.append(float(row[2]))
                retransmissions.append(float(row[3]))

    # Plot throughput vs time
    plt.plot(times, throughput, label="Throughput (Bps)")
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Bps)")
    plt.title("Throughput vs Time")
    plt.legend()
    plt.show()

    # Plot retransmissions vs time
    plt.plot(times, retransmissions, label="Retransmissions", color="red")
    plt.xlabel("Time (s)")
    plt.ylabel("Retransmissions (%)")
    plt.title("Retransmissions vs Time")
    plt.legend()
    plt.show()

