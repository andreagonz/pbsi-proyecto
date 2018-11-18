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
			    beginAtZero:true,
                            stepSize: 1
			}
		    }]
		},
		animation : {
		    onComplete : function(){
			const imgWrap = document.getElementById('descarga-top5-paises')
			imgWrap.href = document.getElementById("top5-paises").toDataURL();
		    }
		},
		title: {
		    display: true,
		    text: 'Top 5 Países',
		    fontSize: 16
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
			    beginAtZero: true,
                            stepSize: 1
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
		    text: 'Top 5 Hosting',
		    fontSize: 16
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
		    text: 'Sectores Afectados',
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
		    text: 'Entidades Afectadas',
		    fontSize: 16
		}
	    }	    
	});

        
    },
    error: function(error_data) {
	console.log("Error al crear gráficas")
    }
})
