use pdns;


#............. fastflux ..................
DROP TABLE IF EXISTS demo1_fastflux;
CREATE TEMPORARY TABLE IF NOT EXISTS ff_daysback AS (SELECT query AS query_temp FROM pdns_pri WHERE (LAST_SEEN >= (CURDATE() - INTERVAL 30 DAY)) AND (query NOT REGEXP 'netapplications.com|mobilecore|pool.ntp|akamai|chartbeat|amazonaws|google|cloudfront|gstatic|mobileapptracking.com|adnxs|cdngc.net|akadns')); # data<30 dni, bez blbosti ako akamai
CREATE TEMPORARY TABLE IF NOT EXISTS ff_freq_queries AS (SELECT query_temp FROM ff_daysback GROUP BY query_temp HAVING COUNT(query_temp) > 50); # queries s vyssou pocetnostou. FF sa prejavuje pocetnou zmenou IP/FQDN
CREATE TABLE demo1_fastflux AS (SELECT * FROM pdns_pri RIGHT JOIN ff_freq_queries ON pdns_pri.query = ff_freq_queries.query_temp WHERE pdns_pri.query NOT REGEXP 'cloudscaler.org' ORDER BY pdns_pri.query); #duplicitne FQDN/query (t.j. odlisna IP pre dane FQDN)


#............. low TTL ..................
DROP TABLE IF EXISTS demo2_lowttl;
CREATE TEMPORARY TABLE IF NOT EXISTS rawlog_lowttl AS (SELECT * FROM rawlog_pri WHERE ttl<5); #rawlog s nizkym TTL. Zaujima ma cely riadok.
CREATE TABLE demo2_lowttl AS (SELECT * FROM rawlog_lowttl WHERE time >= (CURDATE() - INTERVAL 10 DAY) AND query NOT REGEXP 'akamai|chartbeat|amazonaws|google|cloudfront|gstatic|adnxs|cdngc.net' ORDER BY time DESC); # data<10 dni, bez blbosti ako akamai


#............. domain hijack ..................
DROP TABLE IF EXISTS demo3_domhijack;
CREATE TEMPORARY TABLE IF NOT EXISTS ns_changing AS (SELECT query AS query_temp FROM pdns_pri WHERE maptype = 'NS' GROUP BY query HAVING COUNT(query) > 4); # zgrupovane NS queries, ktore mali rozne odpovede
CREATE TEMPORARY TABLE IF NOT EXISTS ns_only AS (SELECT * FROM pdns_pri WHERE MAPTYPE = 'NS' AND query NOT REGEXP 'in_addr.arpa|cloudfront' AND query !='' AND ANSWER != ''); # z pdns_pri odfiltrujem plevelne NS dotazy
#81 sec. pre NS>2
CREATE TABLE demo3_domhijack AS (SELECT * FROM ns_only RIGHT JOIN ns_changing ON ns_only.query = ns_changing.query_temp ORDER BY ns_only.query); # hladam pr1enik unikatnych viacnasobnych NS dotazov a ocistenej pdns_pri tabulke


#............. cachepoison ..................
DROP TABLE IF EXISTS demo4_cachepoison;
CREATE TEMPORARY TABLE IF NOT EXISTS hijack_daysback_a AS (SELECT * FROM pdns_pri WHERE LAST_SEEN >= (CURDATE() - INTERVAL 30 DAY) AND MAPTYPE = 'A'); # data<30 dni. Neodfiltrujem caste domeny ako pre fastflux, lebo prave tie ma zaujimaju.
#250 sec.
CREATE TEMPORARY TABLE IF NOT EXISTS hijack_daysback_a_alexaonly AS (SELECT * FROM hijack_daysback_a RIGHT JOIN alexa ON hijack_daysback_a.query = alexa.domain); # filtrujem dalej len alexa domeny
CREATE TEMPORARY TABLE IF NOT EXISTS hijack_relevant_queries AS (SELECT * FROM hijack_daysback_a_alexaonly GROUP BY query HAVING COUNT(query) > 2); # vyberam subset queries, ktore sa vyskytuju viackrat a tie nasledne pouzijem ako dalsi filter.
CREATE TABLE demo4_cachepoison AS (SELECT hijack_daysback_a_alexaonly.* FROM hijack_daysback_a_alexaonly RIGHT JOIN hijack_relevant_queries on hijack_daysback_a_alexaonly.query = hijack_relevant_queries.query ORDER BY hijack_daysback_a_alexaonly.query); #subset viacnasobnych pouzijem ako filter


#............. Typo, IDN ..................
DROP TABLE IF EXISTS demo5_typo;
CREATE TABLE demo5_typo AS SELECT * FROM rawlog_pri WHERE query REGEXP '^xn--' UNION ALL SELECT * FROM rawnxlog_pri WHERE query REGEXP '^xn--';


#............. previously unseen ..................
DROP TABLE IF EXISTS demo6_unseen;
#CREATE TEMPORARY TABLE IF NOT EXISTS average_visits AS (SELECT query FROM pdns_pri WHERE (LAST_SEEN BETWEEN (CURDATE() - INTERVAL 30 DAY) AND (CURDATE() - INTERVAL 10 DAY)) GROUP BY query); # data stare 10 az 30 dni, unique queries
#CREATE TEMPORARY TABLE IF NOT EXISTS last_visits AS (SELECT * FROM pdns_pri WHERE (LAST_SEEN >= (CURDATE() - INTERVAL 10 DAY))); # nedavne queries
#CREATE TEMPORARY TABLE IF NOT EXISTS last_vis_subquery AS (SELECT SUBSTRING_INDEX(query, '.', -2) AS subquery FROM last_visits GROUP by subquery); # orezavam len 2nd level domain, aby som setril vykon
#CREATE TEMPORARY TABLE IF NOT EXISTS average_vis_subquery AS (SELECT SUBSTRING_INDEX(query, '.', -2) AS subquery FROM average_visits GROUP BY subquery); # orezavam len 2nd level domain, aby som setril vykon
#CREATE TABLE demo6_unseen AS (SELECT last_vis_subquery.subquery FROM last_vis_subquery LEFT JOIN average_vis_subquery ON last_vis_subquery.subquery = average_vis_subquery.subquery WHERE average_vis_subquery.subquery IS null);

#Zoznam unikatnych queries. Dobre tu a tam robit nanovo.
#DROP TABLE IF EXISTS uniq_queries;
#CREATE TABLE uniq_queries AS (SELECT DISTINCT(substring_index(query, '.', '-2')) AS uniq_query FROM pdns_pri);

CREATE TEMPORARY TABLE IF NOT EXISTS last_visits AS (SELECT * FROM pdns_pri WHERE (LAST_SEEN >= (CURDATE() - INTERVAL 2 DAY))); # nedavne queries
CREATE TEMPORARY TABLE IF NOT EXISTS last_vis_subquery AS (SELECT SUBSTRING_INDEX(query, '.', -2) AS subquery FROM last_visits GROUP by subquery); # orezavam len 2nd level domain, aby som setril vykon
CREATE TABLE demo6_unseen AS (SELECT last_vis_subquery.subquery FROM last_vis_subquery LEFT JOIN uniq_queries ON last_vis_subquery.subquery = uniq_queries.uniq_query WHERE uniq_queries.uniq_query IS null);


#............. longdomains ..................
DROP TABLE IF EXISTS demo7_long;
CREATE TABLE demo7_long AS (SELECT * FROM pdns_pri WHERE char_length(query)>80 AND query NOT REGEXP 'mcafee');


#............. TLD appending ..................
### CDNky a google casto false positives. Mozno odfiltrovat. DLHE execution, treba optimalizovat performance. 1000 zaznamov 30s, 600 000 zaznamov zrejme 1800s (30 min.)
DROP TABLE IF EXISTS demo8_append;
CREATE TEMPORARY TABLE IF NOT EXISTS alexa_dot AS (SELECT CONCAT(domain,'.') AS domain_dot FROM alexa WHERE domain NOT REGEXP 'google'); #doplnim bodku za alexa domey, aby som vytvoril string, kde alexa domena neukoncuje hostname, ale este nieco za nou nasleduje
CREATE TABLE demo8_append AS SELECT * FROM pdns_pri RIGHT JOIN alexa_dot ON pdns_pri.query REGEXP alexa_dot.domain_dot LIMIT 1000;


#............. subdomain ..................
DROP TABLE IF EXISTS demo9_subdomain;
CREATE TABLE demo9_subdomain AS (SELECT * FROM pdns_pri WHERE LENGTH(query) - LENGTH(REPLACE(query, '.', '')) between 15 and 127); #bodka sa nachadza viac krat


#............. nx requests ..................
DROP TABLE IF EXISTS demo10_nxreq;
CREATE TABLE demo10_nxreq AS (SELECT query, COUNT(*) AS count_x FROM rawnxlog_pri WHERE query NOT REGEXP 'in-addr.arpa' GROUP BY query ORDER BY COUNT(*) DESC);


#............. nxclient ..................
DROP TABLE IF EXISTS demo11_nxclient;
CREATE TABLE demo11_nxclient AS (SELECT client_ip, COUNT(*) AS count_x FROM rawnxlog_pri GROUP BY client_ip ORDER BY COUNT(*) DESC);


#............. txt ..................
DROP TABLE IF EXISTS demo12_txt;
CREATE TABLE demo12_txt AS (SELECT * FROM pdns_pri WHERE (maptype='TXT' AND query NOT REGEXP 'sophos|e5.sk' AND query REGEXP 'logmein|net') );


#............. geolocation ..................
DROP TABLE IF EXISTS demo13_geo;
CREATE TABLE demo13_geo AS (SELECT * FROM geoip_pri GROUP by geolocation);


#............. malware ..................
DROP TABLE IF EXISTS demo14_malware;
CREATE TABLE demo14_malware AS (SELECT * FROM pdns_pri RIGHT JOIN malware_dom ON pdns_pri.query = malware_dom.malware_dom WHERE pdns_pri.query IS NOT null); # hladam pr1enik tabuliek pdns a malware_dom

