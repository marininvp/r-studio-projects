# Сбор и аналитическая обработка информации о сетевом трафике

## Практическое задание №3

### Описание

#### Вы – специалист по информационной безопасности компании “СуперМегатек”.
#### Вы часто используете информацию о сетевом трафике для обнаружения подозрительной и вредоносной активности.  
#### Помогите защитить Вашу компанию от международной хакерской группировки AnonMasons.
#### • Описание полей датасета: timestamp,src,dst,port,bytes
#### • IP адреса внутренней сети начинаются с 12-14
#### • Все остальные IP адреса относятся к внешним узлам

### Задание 3

#### Еще один нарушитель собирает содержимое электронной почты и отправляет в Интернет используя порт, который обычно используется для другого типа трафика.
#### Атакующий пересылает большое количество информации используя этот порт, которое нехарактерно для других хостов, использующих этот номер порта.
#### Определите IP этой системы. Известно, что ее IP адрес отличается от нарушителей из предыдущих задач.

### Подключение библиотек

    knitr::opts_chunk$set(echo = TRUE)
    library(arrow)
    library(dplyr)
    library(stringr)
    library(lubridate)
    library(cluster)
    library(ggplot2)
    
### Загрузка данных

    new_data <- arrow::read_csv_arrow("D:\\ProjectsRstudio\\2_sem_R\\LAB1\\gowiththeflow_20190826.csv",schema=schema(timestamp=int64(),src=utf8(),dst=utf8(),port=int32(),bytes=int32()))
    
## Решение задачи 3

### Фильтрация

    sel<-filter(new_data, str_detect(src,"^((12|13|14)\\.)"),str_detect(dst,"^((12|13|14)\\.)",negate=TRUE))%>%
      select(port,bytes,src)
    sam<-sel[order(sel$port, decreasing = TRUE), ]%>%group_by(src,port)
    sam2<-sam%>% summarize(b_src_port = sum(bytes))%>%group_by(port)
    sam3<-sam2 %>% summarize(b_port = mean(b_src_port))
    sam4<-merge(sam, sam3, by = "port")
    sam4$diff <- sam4$bytes - sam4$b_port
    sam4[order(sam4$diff, decreasing = TRUE), ]
    res<-filter(sam4,str_detect(src,"13.37.84.125",negate=TRUE)&str_detect(src,"13.48.72.30",negate=TRUE)) %>% head(1)
    res %>% select(src)

    ## # A tibble: 1 × 1
    ##   src         
    ##   <chr>       
    ## 1 14.49.44.92
  
### Ответ: 14.49.44.92