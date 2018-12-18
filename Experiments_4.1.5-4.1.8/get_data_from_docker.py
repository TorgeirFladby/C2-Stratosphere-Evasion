import docker
import collections

client = docker.from_env()
all_containers = client.containers.list(all=True)
relevant_containers = all_containers[:25]
container_dict = collections.defaultdict(list)

for i in relevant_containers:
    print(i.labels)
    if "random" in i.name:
        container_dict["1-random-perturbation"].append(i)
    elif "2-adaptive" in i.name:
        container_dict["2-adaptive-stepsize"].append(i)
    elif "3-simultaneous" in i.name:
        container_dict["3-simultaneous-perturbation"].append(i)
    elif "4-learning-automata" in i.name:
        container_dict["4-learning-automata"].append(i)
    elif "5-learning-automata-euclidean" in i.name:
        container_dict["5-learning-automata-euclidean"].append(i)

for k, v in container_dict.items():
    counter = 0
    for i in v:
        filename = i.name + ".tar"
        f = open(filename, "wb")
        bits, stat = i.get_archive("home/ubuntu/SlipsExperiments/data")
        for chunk in bits:
            f.write(chunk)
        f.close()
