import pandas as pd
import sys

print (sys.path)
            
# reading csv files
data1 = pd.read_csv('{{ output_path }}/{{ filename }}')
data2 = pd.read_csv('{{ output_path }}/{{ filename2 }}')
datavlan = pd.read_csv('{{ output_path }}/{{ filenamevlan }}')
# remove spaces from column names
data2.columns = data2.columns.str.replace(' ', '')
# using merge function by setting how='inner'
output1 = pd.merge(data2, data1, 
                  on='interface', 
                  how='inner')                        
# find interfaces with 0 Bytes
df = output1[output1['InBytes'] == 0]
df = df.drop(columns=['InUcastPkts','InMcastPkts','InBcastPkts'])
df.set_index('interface')
# displaying result
print(df)
df.to_csv('{{ output_path }}/{{ filename3 }}', index = False)
#repeat inner join with csv3
data3 = pd.read_csv('{{ output_path }}/{{ filename3 }}')

# using merge function by setting how='inner'
output2 = pd.merge(data3, datavlan, 
                  on='interface', 
                  how='inner')   
# move interface column to front
column_to_move = output2.pop("interface")
output2.insert(0, "interface", column_to_move )
# move bytes column to last
column_to_move2 = output2.pop("InBytes")
output2.insert(len(output2.columns), "InBytes", column_to_move2 )
# eliminate index numbers in output csv
output2.set_index('interface')
output2.to_csv('{{ output_path }}/{{ filename4 }}', index = False, float_format='%.0f')
print(output2)