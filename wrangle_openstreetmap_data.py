# Cleans and explorts OpenStreetMap data into csv's for import into an SQL database.
####################################################################################

# Import Statements
##################

import xml.etree.cElementTree as ET
import csv
import re
import sys
import codecs
import string
import logging

# Global Constants
##################

NODE_COLUMNS = ['id', 'lat', 'lon', 'user', 'uid', 'version', 'changeset', 'timestamp']
TAG_COLUMNS = ['id', 'key', 'value', 'type']
WAY_COLUMNS = ['id', 'user', 'uid', 'version', 'timestamp', 'changeset']
WAY_NODES_COLUMNS = ['id', 'node_id', 'position']

NODES_PATH = "nodes.csv"
NODE_TAGS_PATH = "nodes_tags.csv"
WAYS_PATH = "ways.csv"
WAY_NODES_PATH = "ways_nodes.csv"
WAY_TAGS_PATH = "ways_tags.csv"

SCHEMA_DICT = {'node': NODE_COLUMNS, 
               'tag': TAG_COLUMNS,
               'way': WAY_COLUMNS,
               'nd': WAY_NODES_COLUMNS}

# Change this to match the filename of the OSM file you'd like to parse. 
#filename ='los-angeles_california.osm'
filename = 'sample_los-angeles-california.osm'

logging.basicConfig(filename='parsing.log', level=logging.INFO)

LOWER_COLON = re.compile(r'^([a-z]|_)+:([a-z]|_)+')
PROBLEMCHARS = re.compile(r'[=\+/&<>;\'"\?%#$@\,\. \t\r\n]')

# Helper methods
################

def get_element(osm_file, tags=('node', 'way')):
    """Yield Element if it is the right type of tag"""
    context = ET.iterparse(osm_file, events=('start', 'end'))
    _, root = next(context)
    for event, element in context:
        if event == 'end' and element.tag in tags:
            yield element
            root.clear()

def format_tag_key(tag, key='key'):
    """Returns seperate, corrected key and type values"""
    if PROBLEMCHARS.search(tag[key]) is None:
        if bool(LOWER_COLON.search(tag[key])):
            split_tag = tag[key].split(':', 1)
            tag[key] = split_tag[1]
            tag['type'] = split_tag[0]
        else:
            tag['type'] = 'regular'
    else:
        logging.info('Tag has problem character: %s skipping.', repr(tag[key]))
        tag['type'] = 'skip'
    return tag

def new_shape_element(element):
    """Returns dict correctly shaped for writing to csv file"""
    row = {}
    tags = []
    nds= []
    
    for attribute in SCHEMA_DICT[element.tag]:
        if attribute in element.attrib.keys():
            row[attribute] = element.attrib[attribute]
    shaped_dict = {element.tag : row}
    
    for tag in element.iter('tag'):
        tag_as_dict = {'id':row['id'], 'key':tag.attrib['k'], 'value':tag.attrib['v'], 'type':'regular'}
        tag_as_dict = format_tag_key(tag_as_dict)
        if tag_as_dict['type'] != 'skip':
            tags.append(tag_as_dict)
    if tags:
        shaped_dict['tags'] = tags
    
    for position, nd in enumerate(element.iter('nd')):
        nd_as_dict = {'id':row['id'], 'node_id':nd.attrib['ref'], 'position':position}
        nds.append(nd_as_dict)
    if nds:
        shaped_dict['way_nodes'] = nds
    
    return shaped_dict


def add_row_to_csv(filename, row, fieldnames):
    with open(filename, 'wb') as f:
        writer = csv.DictWriter(sys.stderr, fieldnames=fieldnames)
        writer.writerow(row)

class UnicodeDictWriter(csv.DictWriter, object):
    """Extend csv.DictWriter to handle Unicode input"""

    def writerow(self, row):
        super(UnicodeDictWriter, self).writerow({
            k: (v.encode('utf-8') if isinstance(v, unicode) else v) for k, v in row.iteritems()
        })

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


# Data Auditing Functions 
##########################

street_type_re = re.compile(r'\b\S+\.?$', re.IGNORECASE)
is_postcode_re = re.compile('^\d{5}$')
is_postcode_plus_four_re = re.compile(r'.*(\d{5}(\-\d{4}))$')

expected_streetnames = ["Street", "Avenue", "Boulevard", "Drive", "Court", "Place", "Square", "Lane", "Road", 
            "Trail", "Parkway", "Commons", "Highway", "Pike", "Way", "Circle", "Terrace", "Alley","Canal","Center","Circle",
                       "Cove", "Trail", "Way" ]
streetname_mapping = {'Al':'Alley',
                     'Ave':'Avenue',
                     'Av':'Avenue',
                     'Blvd':'Boulevard',
                     'Bv':'Boulevard',
                      'Boulvard':'Boulevard',
                      'Ca':'Canal',
                      'Cn':'Center',
                      'Cr':'Cirle',
                      'Cir':'Circle',
                      'Ct':'Court',
                      'Cv':'Cove',
                      'Dr': 'Drive',
                      'Hwy':'Highway',
                     'Pkwy': 'Parkway',
                      'Pky':'Parkway',
                      'Pl':'Place',
                     'Rd':'Road',
                     'St':'Street',
                      'Sq':'Square',
                      'Tr':'Trail',
                      'Trl':'Trail',
                      'Ln': 'Lane',
                     'Wy':'Way',
                     }

def correct_streetname(streetname):
    """Returns a corrected streetname"""
    
    #Capitalize all words in streetname string, remove any '.'s 
    streetname_capitalized = string.capwords(streetname).replace('.', '')

    #Grab just the type of street (ie Avenue, or Ave)
    street_type = street_type_re.search(streetname_capitalized)
    
    #Provided there is a street type, correct if not formatted as expected. 
    if street_type is not None:
        street_type = street_type.group()
        if street_type not in expected_streetnames:
            if street_type in streetname_mapping:
                new_street_type = streetname_mapping[street_type]
                streetname = streetname_capitalized.replace(street_type, new_street_type)
            else:
                streetname = streetname_capitalized
                logging.info("No streetname mapping correction: %s", streetname)
        else:
            streetname = streetname_capitalized
    else:
        logging.info('street_type is NONE with this streetname: %s', streetname)
    #TODO Add support for Spanish Street Prefixes
    return streetname

   
def correct_zipcode(zipcode):
    """Returns a corrected zipcode"""
    if is_postcode_re.search(zipcode) is None:
        if is_postcode_plus_four_re.match(zipcode) is not None:
            zipcode =  zipcode[:5]
        elif zipcode[:3].upper() == 'CA ':
            zipcode = zipcode[3:]
            if is_postcode_re.search(zipcode) is not None:
                return zipcode
            else:
                zipcode = ''
        elif is_postcode_re.search(zipcode.replace(' ', '')) is not None:
            return zipcode.replace(' ', '')
        else:
            zipcode = ''
    return zipcode


def is_zip_in_california(zipcode):
    """Checks if the zipcode could be in California"""
    #First three digits of zip should be between 900 and 961 
    if zipcode is not '':
        try:
            if 900 <= int(zipcode[:3]) <= 961:
                return True
            else:
                logging.info('Non CA zip code found: %s', zipcode)
                return False
        except:
            logging.info("Can't check for Califonia: ", zipcode)

# Main
#######

with codecs.open(NODES_PATH, 'w') as nodes_file, \
    codecs.open(NODE_TAGS_PATH, 'w') as nodes_tags_file, \
    codecs.open(WAYS_PATH, 'w') as ways_file, \
    codecs.open(WAY_NODES_PATH, 'w') as way_nodes_file, \
    codecs.open(WAY_TAGS_PATH, 'w') as way_tags_file:

    nodes_writer = UnicodeDictWriter(nodes_file, NODE_COLUMNS)
    node_tags_writer = UnicodeDictWriter(nodes_tags_file, TAG_COLUMNS)
    ways_writer = UnicodeDictWriter(ways_file, WAY_COLUMNS)
    way_nodes_writer = UnicodeDictWriter(way_nodes_file, WAY_NODES_COLUMNS)
    way_tags_writer = UnicodeDictWriter(way_tags_file, TAG_COLUMNS)

    nodes_writer.writeheader()
    node_tags_writer.writeheader()
    ways_writer.writeheader()
    way_nodes_writer.writeheader()
    way_tags_writer.writeheader()

    for element in get_element(filename):
        element_to_write = new_shape_element(element)
        if 'tags' in element_to_write:
            for tag in element_to_write['tags']:
                if tag['key'] == 'street':
                    tag['value'] = correct_streetname(tag['value'])
                if tag['key'] == 'postcode':
                    new_zip = correct_zipcode(tag['value'])
                    if is_zip_in_california(new_zip):
                        tag['value'] = new_zip
                    else: 
                        tag['value'] = ''

        if 'node' in element_to_write:
            nodes_writer.writerow(element_to_write['node'])
            if 'tags' in element_to_write:
                node_tags_writer.writerows(element_to_write['tags'])
        if 'way' in element_to_write:
            ways_writer.writerow(element_to_write['way'])
            if 'way_nodes' in element_to_write:
                way_nodes_writer.writerows(element_to_write['way_nodes'])
            if 'tags' in element_to_write:
                way_tags_writer.writerows(element_to_write['tags']) 

logging.info('Finished')