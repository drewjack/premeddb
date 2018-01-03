import bs4 as bs
import urllib.request
import csv


def medlist():
    sauce = urllib.request.urlopen('https://en.wikipedia.org/wiki/List_of_medical_schools_in_the_United_States').read()
    soup = bs.BeautifulSoup(sauce,'lxml')

    table = soup.find('table')

    table_rows = table.find_all('tr')
    medlist = []
    for tr in table_rows[1:]:
        td = tr.find_all('td')
        row = [i.text for i in td]
        a = 'https://en.wikipedia.org' + tr.find_all('a')[1].get('href')
        medschool = [row[1], row[0], row[2], row[3], a]
        medlist.append(medschool)
    return medlist

medschooldata = medlist()
def medschoollink():
    linkresult = []
    linkadd = []
    for medschool in medschooldata:
        try:
            sauce = urllib.request.urlopen(medschool[4])
            soup = bs.BeautifulSoup(sauce, 'lxml')

            # table = soup.find("table", {"class": "infobox vcard"})
            # table_a = table.find_all('a')
            # linkresult.append(soup.find("a", rel="nofollow").get('href'))
            value = soup.find("a", rel="nofollow").get('href')
            linkresult = medschool
            linkresult.append(value)
        except:
            print('blank')
        print(linkresult)
        linkadd.append(linkresult)
    return linkadd

with open("medschooldata.csv", "w") as f:
    writer = csv.writer(f)
    writer.writerows(medschoollink())

    #Issues swith Columbia,
    # Stony Brook,
    # University of Missouri–Kansas City School of Medicine,
    # Harvard Medical School,
    # University of Maryland School of Medicine,
    # Louisiana State University School of Medicine in Shreveport
    # University of Chicago Pritzker School of Medicine
    # Howard University College of Medicine
    # Florida Atlantic University Charles E. Schmidt College of Medicine
    # University of California, Irvine School of Medicine
