import argparse
import json
import os
import shutil

from mininet.log import LEVELS, lg


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--input-dir', help='Input directory containing topologies',
                        default='/home/jadinm/repositories/SRv6/rerouting/test/examples/'
                                '2016TopologyZooUCL_inverseCapacity')
    parser.add_argument('--json-improvement-data', help='JSON containing theoritical improvements',
                        default='/home/jadinm/repositories/SRv6/rerouting/test/examples/improvement_combinations.json')
    parser.add_argument('--output-dir', help='JSON containing theoritical improvements',
                        default='/home/jadinm/repositories/SRv6/rerouting/test/examples/2016TopologyZooUCL_filtered_50')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    try:
        os.mkdir(args.output_dir)
    except OSError as e:
        if e.errno != 17:
            raise e

    with open(args.json_improvement_data) as fileobj:
        improvements = json.load(fileobj)

    for elem in improvements:
        topo = elem["topo"]
        demands = elem["demands"]
        improvement = elem["improvement"]
        if improvement >= 50:
            shutil.copy(os.path.join(args.input_dir, topo), os.path.join(args.output_dir, topo))
            shutil.copy(os.path.join(args.input_dir, demands), os.path.join(args.output_dir, demands))
