var endpoint = '/api/chart/data/'
var defaultData = []
var labels = []

$.ajax({
    method: "GET",
    url: endpoint,
    success: function(graphs) {
        var paises = graphs[0].labels        
	var cuenta_paises = graphs[0].default
	var paises_canvas = document.getElementById("top5-paises");
	var top_paises = new Chart(paises_canvas, {
	    type: 'bar',
	    data: {
		labels: paises,
		datasets: [{
		    label: '',
		    data: cuenta_paises,
		    backgroundColor: [
			'rgba(255, 99, 132, 0.2)',
			'rgba(54, 162, 235, 0.2)',
			'rgba(255, 206, 86, 0.2)',
			'rgba(75, 192, 192, 0.2)',
			'rgba(153, 102, 255, 0.2)',
			'rgba(255, 159, 64, 0.2)'
		    ],
		    borderColor: [
			'rgba(255,99,132,1)',
			'rgba(54, 162, 235, 1)',
			'rgba(255, 206, 86, 1)',
			'rgba(75, 192, 192, 1)',
			'rgba(153, 102, 255, 1)',
			'rgba(255, 159, 64, 1)'
		    ],
		    borderWidth: 1
		}],
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: false,
		scales: {
		    yAxes: [{
			ticks: {
			    beginAtZero:true
			}
		    }]
		},
		animation : {
		    onComplete : function(){
			// const imgWrap = document.getElementById('descarga-top5-paises')
			// imgWrap.href = document.getElementById("top5-paises").toDataURL();
		    }
		},
		title: {
		    display: true,
		    text: ['TOP 5 PAÍSES','Top 5 países que hospedan sitios phishing'],
		    fontSize: 16
		},
                legend: {
                    labels: {
                        boxWidth: 0,
                    }
                }
	    }
	});

        var hosting = graphs[1].labels
	var cuenta_hosting = graphs[1].default
	var hosting_canvas = document.getElementById("top5-hosting");
	var top_hosting = new Chart(hosting_canvas, {
	    type: 'bar',
	    data: {
		labels: hosting,
		datasets: [{
		    label: '',
		    data: cuenta_hosting,
		    backgroundColor: [
			'rgba(255, 99, 132, 0.2)',
			'rgba(54, 162, 235, 0.2)',
			'rgba(255, 206, 86, 0.2)',
			'rgba(75, 192, 192, 0.2)',
			'rgba(153, 102, 255, 0.2)',
			'rgba(255, 159, 64, 0.2)'
		    ],
		    borderColor: [
			'rgba(255,99,132,1)',
			'rgba(54, 162, 235, 1)',
			'rgba(255, 206, 86, 1)',
			'rgba(75, 192, 192, 1)',
			'rgba(153, 102, 255, 1)',
			'rgba(255, 159, 64, 1)'
		    ],
		    borderWidth: 1
		}]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: false,
		scales: {
		    yAxes: [{
			ticks: {
			    beginAtZero: true
			}
		    }],
                    xAxes: [{
			ticks: {
			    display: false
			}
		    }]
		},
		animation : {
		    onComplete : function(){
			// const imgWrap = document.getElementById('descarga-top5-paises')
			// imgWrap.href = document.getElementById("top5-paises").toDataURL();
		    }
		},
		title: {
		    display: true,
		    text: ['TOP 5 HOSTING', 'Top 5 servicios de hosting que hospedan sitios phishing'],
		    fontSize: 16
		},
                legend: {
                    labels: {
                        boxWidth: 0,
                    }
                }
	    }
	});
        
        var sitios = graphs[2].labels
	var cuenta_sitios = graphs[2].default
	var sitios_canvas = document.getElementById("sitios-phishing");
	var sitiosGraph = new Chart(sitios_canvas, {
	    type: 'bar',
	    data: {
		labels: sitios,
		datasets: [{
		    label: '',
		    data: cuenta_sitios,
		    backgroundColor: [
			'rgba(255, 99, 132, 0.2)',
			'rgba(54, 162, 235, 0.2)',
			'rgba(255, 206, 86, 0.2)'
		    ],
		    borderColor: [
			'rgba(255,99,132,1)',
			'rgba(54, 162, 235, 1)',
			'rgba(255, 206, 86, 1)'
		    ],
		    borderWidth: 1
		}]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: false,
		scales: {
		    yAxes: [{
			ticks: {
			    beginAtZero: true
			}
		    }]
		},
		animation : {
		    onComplete : function(){
		    }
		},
		title: {
		    display: true,
		    text: ['SITIOS PHISHING', 'Número de sitios phishing detectados, activos y reportados'],
		    fontSize: 16
		},
                legend: {
                    labels: {
                        boxWidth: 0,
                    }
                }
	    }
	});
        
        var urls = graphs[3].labels
	var tiempo_vida = graphs[3].default
	var sitios_canvas = document.getElementById("top5-sitios");
	var tiempo_vida = new Chart(sitios_canvas, {
	    type: 'horizontalBar',
	    data: {
		labels: urls,
		datasets: [{
		    label: '',
		    data: tiempo_vida,
		    backgroundColor: [
			'rgba(255, 99, 132, 0.2)',
			'rgba(54, 162, 235, 0.2)',
			'rgba(255, 206, 86, 0.2)',
			'rgba(75, 192, 192, 0.2)',
			'rgba(153, 102, 255, 0.2)',
			'rgba(255, 159, 64, 0.2)'
		    ],
		    borderColor: [
			'rgba(255,99,132,1)',
			'rgba(54, 162, 235, 1)',
			'rgba(255, 206, 86, 1)',
			'rgba(75, 192, 192, 1)',
			'rgba(153, 102, 255, 1)',
			'rgba(255, 159, 64, 1)'
		    ],
		    borderWidth: 1
		}]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: false,
		scales: {
		    xAxes: [{
			ticks: {
			    beginAtZero: true
			},
                        scaleLabel: {
                            display: true,
                            labelString: 'T (Horas)'
                        }
		    }],
                    yAxes: [{
                        barThickness: 10,                        
		    }]
		},
		animation : {
		    onComplete : function(){
			// const imgWrap = document.getElementById('descarga-top5-paises')
			// imgWrap.href = document.getElementById("top5-paises").toDataURL();
		    }
		},
		title: {
		    display: true,
		    text: ['TOP 5 - SITIOS VS TIEMPO DE VIDA', 'Top 5 sitios phishing con mayor tiempo de vida desde su registro en el sistema'],
		    fontSize: 16
		},
                legend: {
                    labels: {
                        boxWidth: 0,
                    }
                }
	    }
	});
        
        var sectores = graphs[4].labels
	var cuenta_sectores = graphs[4].default
	var sectores_canvas = document.getElementById("sectores");
        var colores_sectores = graphs[4].colores
        var pieSectores = new Chart(sectores_canvas, {
	    type: 'pie',
	    data: {
		labels: sectores,
		datasets: [
		    {
			data: cuenta_sectores,
			backgroundColor: colores_sectores
		    }]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: true,
		animation : {
		    onComplete : function(){
		    }
		},
		title: {
		    display: true,
		    text: ['SECTORES AFECTADOS', 'Sectores que han sido afectados por sitios phishing'],
		    fontSize: 16
		}
	    }
	    
	});
        
        var dias = graphs[5].labels
	var cuenta_detecciones = graphs[5].default
        var detecciones_canvas = document.getElementById("detecciones");
        var deteccionesGraph = new Chart(detecciones_canvas, {
	    type: 'line',
	    data: {
		labels: dias,
		datasets: [
		    {
			data: cuenta_detecciones,
			label: "Número de Detecciones",
			lineTension: 0,
			fill: false,
			borderColor: 'orange',
			backgroundColor: 'transparent',
			borderDash: [5, 5],
			pointBorderColor: 'orange',
			pointBackgroundColor: 'rgba(255,150,0,0.5)',
			pointRadius: 5,
			pointHoverRadius: 10,
			pointHitRadius: 30,
			pointBorderWidth: 2,
			pointStyle: 'rectRounded'			
		    }]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: false,
		scales: {
		    yAxes: [{
			ticks: {
			    beginAtZero:true
			}
		    }]
		},
		animation : {
		    onComplete : function(){    
			//var url_base64jp = document.getElementById("top5-count-chart").toDataURL("image/jpg");
			//const imgWrap = document.getElementById('link1')
			//imgWrap.href = url_base64jp 
			//alert(myChart.toBase64Image());
		    }
		},
		title: {
		    display: true,
		    text: ['DETECCIONES EN ÚLTIMOS 7 DÍAS', 'Número de detecciones de sitios phishing por día en la última semana'],
		    fontSize: 16
		}
	    }
	    
	});

        var entidades = graphs[6].labels
	var cuenta_entidades = graphs[6].default
	var entidades_canvas = document.getElementById("entidades");
        var colores_entidades = graphs[6].colores
        var pieEntidades = new Chart(entidades_canvas, {
	    type: 'pie',
	    data: {
		labels: entidades,
		datasets: [
		    {
			data: cuenta_entidades,
			backgroundColor: colores_entidades
		    }]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: true,
		animation : {
		    onComplete : function(){    
		    }
		},
		title: {
		    display: true,
		    text: ['ENTIDADES AFECTADAS', 'Entidades que han sido afectadas por sitios phishing'],
		    fontSize: 16
		}
	    }	    
	});
        
        var tiempo_reporte = graphs[7].default1
	var tiempo_postreporte = graphs[7].default2
        var tiempo_reporte_canvas = document.getElementById("tiempo-reporte");
        var reporteGraph = new Chart(tiempo_reporte_canvas, {
	    type: 'line',
	    data: {
		labels: dias,
		datasets: [
		    {
			data: tiempo_reporte,
			label: "Tiempo promedio de reporte",
			lineTension: 0,
			fill: false,
			borderColor: 'limegreen',
			backgroundColor: 'transparent',
			borderDash: [5, 5],
			pointBorderColor: 'limegreen',
			pointBackgroundColor: 'limegreen',
			pointRadius: 5,
			pointHoverRadius: 10,
			pointHitRadius: 30,
			pointBorderWidth: 2,
			pointStyle: 'rectRounded'			
		    },
                    {
			data: tiempo_postreporte,
			label: "Tiempo promedio de vida postreporte",
			lineTension: 0,
			fill: false,
			borderColor: 'blue',
			backgroundColor: 'transparent',
			borderDash: [5, 5],
			pointBorderColor: 'blue',
			pointBackgroundColor: 'blue',
			pointRadius: 5,
			pointHoverRadius: 10,
			pointHitRadius: 30,
			pointBorderWidth: 2,
			pointStyle: 'rectRounded'			
		    }
                ]
	    },
	    options: {
		responsive: true,
		maintainAspectRatio: false,
		scales: {
		    yAxes: [{
			ticks: {
			    beginAtZero:true,
			},
                        scaleLabel: {
                            display: true,
                            labelString: 'T (Horas)'
                        }
		    }]
		},
		animation : {
		    onComplete : function(){    
			//var url_base64jp = document.getElementById("top5-count-chart").toDataURL("image/jpg");
			//const imgWrap = document.getElementById('link1')
			//imgWrap.href = url_base64jp 
			//alert(myChart.toBase64Image());
		    }
		},
		title: {
		    display: true,
		    text: ['TIEMPO DE REPORTE', 'Tiempo promedio por día de reporte de sitio phishing desde su registro y tiempo', 'promedio por día de vida de sitios phishing después de ser reportados en la última semana'],
		    fontSize: 16
		}
	    }	    
	});
        
    },
    error: function(error_data) {
	console.log("Error al crear gráficas")
    }
})
